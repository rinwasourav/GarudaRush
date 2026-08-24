from setuptools import setup, find_packages

setup(
    name="garuda_rush",
    version="1.0.0",
    description="Intelligent, Real-Time DDoS Detection & Network Analysis System",
    author="Sourav Rinwa",
    author_email="souravrinwa0@gmail.com",
    url="https://github.com/rinwasourav/GarudaRush",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=[
        "Flask",
        "Flask-CORS",
        "pymongo",
        "scapy",
        "requests",
        "numpy",
        "pandas",
        "scikit-learn",
        "joblib",
    ],
)
