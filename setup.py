from setuptools import setup, find_packages

setup(
    name='ooxml_malclassifier',  # Required
    version='1.0',  # Required
    description='OOXML Document Malware Classifier',  # Required
    entry_points={
        'console_scripts': [
            'ooxml_malclassifier = ooxml_malclassifier.mal_classifier:main',
        ],
    },
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),  # Required, packages that will be included in dist
    # package_data={'': ['*.sh', '*.json']},
    install_requires=['olefile>=0.46', 'oletools>=0.54.2', 'requests>=2.22.0', 'lxml>=4.3.3'],
    # setup_requires=['pytest-runner'],  # packages needed to run setup.py
    python_requires='>3.0'
)
