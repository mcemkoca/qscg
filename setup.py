from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="qscg",
    version="4.0.0",
    author="M.Cem Koca",
    author_email="mcemkoca0@gmail.com",
    description="Quantum-Safe Cryptography Infrastructure",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mcemkoca/qscg",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",
    install_requires=requirements,
    extras_require={
        "dev": ["pytest", "pytest-cov", "black", "flake8", "mypy"],
        "docs": ["sphinx", "sphinx-rtd-theme"],
        "gui": ["customtkinter", "Pillow"],
    },
    entry_points={
        "console_scripts": [
            "qscg=qscg.cli:main",
        ],
    },
)
