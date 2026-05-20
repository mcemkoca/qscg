from setuptools import setup, find_packages

setup(
    name="qscg",
    version="3.0.0",
    description="Quantum-Safe Cryptography Toolkit - Post-Quantum Algorithms",
    author="Mehmet Cem Koca",
    author_email="mcemkoca@proton.me",
    url="https://github.com/mcemkoca/qscg",
    packages=find_packages(),
    package_dir={"quantum_safe_crypto": "quantum_safe_crypto"},
    python_requires=">=3.9",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="post-quantum cryptography ml-kem ml-dsa slh-dsa hqc fn-dsa falcon",
)
