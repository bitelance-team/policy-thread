from setuptools import setup, find_packages

setup(
    name="policythread",
    version="0.7.0",
    description="Define what your AI must always do and never do. PolicyThread watches every live interaction and tells you when it breaks the rules.",
    author="Eugene Dayne Mawuli",
    author_email="bitelance.team@gmail.com",
    url="https://github.com/eugene001dayne/policy-thread",
    py_modules=["policythread"],
    install_requires=["httpx"],
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)