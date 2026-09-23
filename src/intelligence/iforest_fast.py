"""
iforest_fast.py – exact single-row IsolationForest scoring without sklearn's per-call overhead.

Why this exists (2026-09-23, live profiling on .94): the pipeline scores one feature
vector per device per cycle. sklearn's decision_function() on a single row costs
~21 ms regardless of the model -- input validation, feature-name checks, warnings
filters and a joblib Parallel dispatch over 100 trees -- which made IsolationForest
scoring 18-26% of the main detection loop's wall time and a large part of the
recurring 15-19 s cycle stalls the freeze watcher recorded.

CompiledIsolationForest reads the fitted trees once into padded numpy arrays and walks
all trees in lock-step, one level per numpy step (max_depth ~8 for max_samples=256).
The arithmetic is the one sklearn uses (sklearn/ensemble/_iforest.py,
_compute_score_samples and _parallel_compute_tree_depths): per-tree leaf value =
decision-path length + average path length of the leaf's sample count - 1, the forest
score is 2 ** (-sum / (n_trees * c(max_samples))), and decision_function is
-score - offset_. Inputs are cast to float32 exactly like sklearn's tree.apply().
tests/test_iforest_fast.py checks equality against sklearn itself.

Anything this does not model (NaN inputs, a model without the expected fitted
attributes) returns None so the caller falls back to sklearn -- never a guess.
"""

from typing import Optional

import numpy as np


class CompiledIsolationForest:
    __slots__ = ("_left", "_right", "_feature", "_threshold", "_leaf_value",
                 "_is_leaf", "_features", "_tree_rows", "_max_depth",
                 "_denominator", "_offset", "n_features_in_")

    def __init__(self, model):
        estimators = model.estimators_
        n_trees = len(estimators)
        node_counts = [est.tree_.node_count for est in estimators]
        width = max(node_counts)

        self._left = np.zeros((n_trees, width), dtype=np.intp)
        self._right = np.zeros((n_trees, width), dtype=np.intp)
        self._feature = np.zeros((n_trees, width), dtype=np.intp)
        self._threshold = np.zeros((n_trees, width), dtype=np.float64)
        self._leaf_value = np.zeros((n_trees, width), dtype=np.float64)
        self._is_leaf = np.ones((n_trees, width), dtype=bool)

        n_features = int(model.n_features_in_)
        subsample = model._max_features != n_features
        # Per-tree column map into the full input row (sklearn: X[:, features]).
        self._features = np.zeros((n_trees, n_features), dtype=np.intp)
        max_depth = 0
        for t, est in enumerate(estimators):
            tree = est.tree_
            n = tree.node_count
            leaf = tree.children_left[:n] == -1
            self._left[t, :n] = np.where(leaf, np.arange(n), tree.children_left[:n])
            self._right[t, :n] = np.where(leaf, np.arange(n), tree.children_right[:n])
            self._feature[t, :n] = np.where(leaf, 0, tree.feature[:n])
            self._threshold[t, :n] = tree.threshold[:n]
            self._is_leaf[t, :n] = leaf
            self._leaf_value[t, :n] = (np.asarray(model._decision_path_lengths[t], dtype=np.float64)
                                       + np.asarray(model._average_path_length_per_tree[t], dtype=np.float64)
                                       - 1.0)
            cols = np.asarray(model.estimators_features_[t]) if subsample else np.arange(n_features)
            self._features[t, :len(cols)] = cols
            max_depth = max(max_depth, int(tree.max_depth))

        self._tree_rows = np.arange(n_trees)
        self._max_depth = max_depth
        # sklearn: _average_path_length([self._max_samples]) for the denominator.
        m = float(model._max_samples)
        if m <= 1:
            c = 0.0
        elif m == 2:
            c = 1.0
        else:
            c = 2.0 * (np.log(m - 1.0) + np.euler_gamma) - 2.0 * (m - 1.0) / m
        self._denominator = n_trees * c
        self._offset = float(model.offset_)
        self.n_features_in_ = n_features

    def decision_function_one(self, vec) -> Optional[float]:
        x = np.asarray(vec, dtype=np.float32).reshape(-1)
        if x.shape[0] != self.n_features_in_ or np.isnan(x).any():
            return None
        x = x.astype(np.float64)
        rows = self._tree_rows
        node = np.zeros(len(rows), dtype=np.intp)
        for _ in range(self._max_depth):
            feat = self._features[rows, self._feature[rows, node]]
            go_left = x[feat] <= self._threshold[rows, node]
            node = np.where(go_left, self._left[rows, node], self._right[rows, node])
        # sklearn accumulates tree by tree; a plain sequential sum keeps the same order.
        depth = float(sum(self._leaf_value[rows, node].tolist()))
        if self._denominator == 0:
            score = 1.0
        else:
            score = 2.0 ** (-depth / self._denominator)
        return -score - self._offset


def compile_model(model) -> Optional[CompiledIsolationForest]:
    """None when the model is not a fitted IsolationForest this module understands."""
    try:
        return CompiledIsolationForest(model)
    except Exception:
        return None
