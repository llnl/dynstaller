import shutil
import sys
from pathlib import Path

import requests

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "dynstaller"
# pylint: disable-next=redefined-builtin
copyright = "2026, Lawrence Livermore National Security"
author = "Asriel Margarian"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.githubpages",
    "sphinx_copybutton",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "images.toml"]

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "furo"
html_theme_options = {
    "source_repository": "https://github.com/llnl/dynstaller",
    "source_branch": "main",
    "source_directory": "docs/",
}

# -- Extension configuration -------------------------------------------------

# Napoleon settings for NumPy and Google style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
#html_logo = "./logos/dynstaller-logo.png"
#html_favicon = html_logo
html_static_path = ["_static"]

# -- Extension - CopyButton - Configuration ----------------------------------

# https://sphinx-copybutton.readthedocs.io/en/latest/use.html#using-regexp-prompt-identifiers
copybutton_prompt_text = r">>> |\.\.\. |\$ |\$\w|In \[\d*\]: | {2,5}\.\.\.: | {5,8}: "
copybutton_prompt_is_regexp = True
# https://sphinx-copybutton.readthedocs.io/en/latest/use.html#honor-here-document-syntax-when-copying-multiline-snippets
copybutton_here_doc_delimiter = "EOT"

base_dir = Path(__file__).parent


# -- Fetch image references --------------------------------------------------
# Download all of the image files referenced in images.toml
def download_images_from_toml(toml_file: Path, image_dir: Path):
    with toml_file.open("rb") as f:
        data = tomllib.load(f)

    if not image_dir.exists():
        image_dir.mkdir(parents=True)

    for file_name, url in data.get("images", {}).items():
        if file_name and url:
            response = requests.get(url)
            if response.status_code == 200:
                with (image_dir / file_name).open("wb") as img_file:
                    img_file.write(response.content)
            else:
                print(f"Failed to download {url}")


# Path to the TOML file
toml_file_path = base_dir / "images.toml"
# Directory to save the images
image_directory = base_dir / "img"

# Download images
download_images_from_toml(toml_file_path, image_directory)
