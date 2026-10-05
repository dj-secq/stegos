import os

def safe_join(directory: str, *paths: str) -> str | None:
    """Safely joins paths, ensuring the result is within the base directory."""
    try:
        final_path = os.path.abspath(os.path.join(directory, *paths))
        base_dir = os.path.abspath(directory)
        
        # Must start with base_dir and not traverse up
        if not final_path.startswith(base_dir):
            return None
            
        # Refuse to process if a component is a symlink pointing outside
        # (For simple containment checking, abspath resolves symlinks on some systems,
        # but to be sure we can check realpath)
        real_path = os.path.realpath(final_path)
        if not real_path.startswith(base_dir):
            return None
            
        return final_path
    except Exception:
        return None
