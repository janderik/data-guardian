from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="dataguardian",
    version="1.0.0",
    description="Data Security Scanner - Detect PII, credentials, and sensitive data",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="DataGuardian Team",
    author_email="dev@dataguardian.io",
    url="https://github.com/yourusername/data-guardian",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    py_modules=["cli"],
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "dataguardian=cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Database",
    ],
    include_package_data=True,
    zip_safe=False,
)
