"""
Attack type classifier using Random Forest.
Classifies detected anomalies into specific attack categories.
"""
import numpy as np
from pathlib import Path
from typing import Optional, Tuple, List
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

from ..utils.config import ATTACK_TYPES, MODELS_DIR
from ..utils.logger import get_logger

logger = get_logger(__name__)


class AttackClassifier:
    """
    Multi-class classifier for attack type classification.
    Uses Random Forest to classify network traffic into attack categories.
    """
    
    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 20,
        random_state: int = 42
    ):
        """
        Initialize the attack classifier.
        
        Args:
            n_estimators: Number of trees in the forest
            max_depth: Maximum depth of trees
            random_state: Random seed for reproducibility
        """
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        
        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.label_encoder = LabelEncoder()
        self.is_fitted = False
        self.classes_ = None
    
    def _map_labels(self, labels: np.ndarray) -> np.ndarray:
        """
        Map detailed attack labels to broader categories.
        
        Args:
            labels: Original attack labels
            
        Returns:
            Mapped category labels
        """
        mapped = []
        for label in labels:
            # Look for matching attack type
            category = ATTACK_TYPES.get(label, 'Unknown Attack')
            mapped.append(category)
        return np.array(mapped)
    
    def fit(self, X: np.ndarray, y: np.ndarray, use_categories: bool = True):
        """
        Train the classifier on labeled data.
        
        Args:
            X: Feature matrix
            y: Attack type labels
            use_categories: Whether to map to broader categories
        """
        logger.info(f"Training attack classifier on {len(X)} samples...")
        
        # Map to categories if requested
        if use_categories:
            y = self._map_labels(y)
        
        # Encode string labels to numbers
        y_encoded = self.label_encoder.fit_transform(y)
        self.classes_ = self.label_encoder.classes_
        
        logger.info(f"Attack categories: {list(self.classes_)}")
        
        # Train the model
        self.model.fit(X, y_encoded)
        self.is_fitted = True
        
        logger.info("Attack classifier training complete")
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict attack types for samples.
        
        Args:
            X: Feature matrix
            
        Returns:
            Array of predicted attack type labels
        """
        if not self.is_fitted:
            raise ValueError("Classifier must be fitted before prediction")
        
        predictions = self.model.predict(X)
        return self.label_encoder.inverse_transform(predictions)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get prediction probabilities for each attack type.
        
        Args:
            X: Feature matrix
            
        Returns:
            Probability matrix (n_samples, n_classes)
        """
        if not self.is_fitted:
            raise ValueError("Classifier must be fitted before prediction")
        
        return self.model.predict_proba(X)
    
    def classify_single(self, x: np.ndarray) -> dict:
        """
        Classify a single sample.
        
        Args:
            x: Single sample (1D array)
            
        Returns:
            Dictionary with classification result
        """
        X = x.reshape(1, -1)
        
        prediction = self.predict(X)[0]
        probabilities = self.predict_proba(X)[0]
        
        # Get probability for the predicted class
        predicted_idx = list(self.classes_).index(prediction)
        confidence = probabilities[predicted_idx]
        
        # Get top 3 predictions
        top_indices = np.argsort(probabilities)[-3:][::-1]
        top_predictions = [
            {
                'attack_type': self.classes_[i],
                'probability': float(probabilities[i])
            }
            for i in top_indices
        ]
        
        return {
            'attack_type': prediction,
            'confidence': float(confidence),
            'top_predictions': top_predictions
        }
    
    def get_feature_importance(self) -> List[Tuple[int, float]]:
        """
        Get feature importance scores.
        
        Returns:
            List of (feature_index, importance) tuples
        """
        if not self.is_fitted:
            raise ValueError("Classifier must be fitted first")
        
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        return [(int(i), float(importances[i])) for i in indices]
    
    def save(self, filepath: Optional[Path] = None):
        """
        Save the classifier to disk.
        
        Args:
            filepath: Path to save the model
        """
        if filepath is None:
            filepath = MODELS_DIR / "attack_classifier.joblib"
        
        joblib.dump({
            'model': self.model,
            'label_encoder': self.label_encoder,
            'classes': self.classes_,
            'n_estimators': self.n_estimators,
            'max_depth': self.max_depth,
            'is_fitted': self.is_fitted
        }, filepath)
        
        logger.info(f"Attack classifier saved to {filepath}")
    
    @classmethod
    def load(cls, filepath: Optional[Path] = None) -> 'AttackClassifier':
        """
        Load a classifier from disk.
        
        Args:
            filepath: Path to the saved model
            
        Returns:
            Loaded AttackClassifier instance
        """
        if filepath is None:
            filepath = MODELS_DIR / "attack_classifier.joblib"
        
        data = joblib.load(filepath)
        
        classifier = cls(
            n_estimators=data['n_estimators'],
            max_depth=data['max_depth']
        )
        classifier.model = data['model']
        classifier.label_encoder = data['label_encoder']
        classifier.classes_ = data['classes']
        classifier.is_fitted = data['is_fitted']
        
        logger.info(f"Attack classifier loaded from {filepath}")
        return classifier


def train_classifier(
    X_train: np.ndarray,
    y_train: np.ndarray,
    save_model: bool = True
) -> AttackClassifier:
    """
    Train an attack classifier and optionally save it.
    
    Args:
        X_train: Training features
        y_train: Training labels (attack types)
        save_model: Whether to save the model
        
    Returns:
        Trained AttackClassifier
    """
    classifier = AttackClassifier()
    classifier.fit(X_train, y_train)
    
    if save_model:
        classifier.save()
    
    return classifier
