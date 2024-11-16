from setuptools import setup, find_packages

setup(
    name="resume_analysis",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "python-dotenv>=0.19.0",
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
        "requests>=2.31.0",
        "PyPDF2>=3.0.0",
        "PyGithub>=1.55",
        "python-linkedin>=2.0",
        "python-dateutil>=2.8.2",
        "asyncio>=3.4.3",
        "regex>=2022.0.0",
        "typing-extensions>=4.0.0"
    ]
) 