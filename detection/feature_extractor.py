import joblib
import os
from scipy.sparse import hstack

# Paths to vectorizers (relative to project root)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WORD_VECTORIZER_PATH = os.path.join(_PROJECT_ROOT, "tfidf_vectorizer.pkl")
_CHAR_VECTORIZER_PATH = os.path.join(_PROJECT_ROOT, "tfidf_char_vectorizer.pkl")

_word_vectorizer = None
_char_vectorizer = None


def _load_vectorizers():
    """Lazy-load the TF-IDF vectorizers."""
    global _word_vectorizer, _char_vectorizer

    if _word_vectorizer is None:
        if os.path.exists(_WORD_VECTORIZER_PATH):
            _word_vectorizer = joblib.load(_WORD_VECTORIZER_PATH)
        else:
            _word_vectorizer = joblib.load("tfidf_vectorizer.pkl")

    if _char_vectorizer is None:
        if os.path.exists(_CHAR_VECTORIZER_PATH):
            _char_vectorizer = joblib.load(_CHAR_VECTORIZER_PATH)
        else:
            _char_vectorizer = joblib.load("tfidf_char_vectorizer.pkl")

    return _word_vectorizer, _char_vectorizer


def extract_features_from_log(log_text):
    """
    Extract features from a log/scenario text using the trained TF-IDF vectorizers.

    Args:
        log_text: Raw text string (log entry or scenario description)

    Returns:
        Sparse matrix of TF-IDF features (word + char n-grams), compatible with model.predict
    """
    word_vec, char_vec = _load_vectorizers()
    text = [str(log_text).strip()]
    X_word = word_vec.transform(text)
    X_char = char_vec.transform(text)
    return hstack([X_word, X_char])