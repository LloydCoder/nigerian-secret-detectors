from setuptools import setup, find_packages

setup(
    name="lloydcoder-nigerian-secrets",
    version="0.1.0",
    author="Lloydcoder",
    description="Nigerian fintech secret detectors CLI",
    packages=find_packages(),
    entry_points={"console_scripts": ["nigerian-scan=runner:main"]},
    install_requires=["subprocess32"],  # Minimal
)
