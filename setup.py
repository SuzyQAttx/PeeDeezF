"""
Setup script for PDF Payload Injector
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'pdf_payload_injector', 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return ''

# Read requirements
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), 'pdf_payload_injector', 'requirements.txt')
    if os.path.exists(requirements_path):
        with open(requirements_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name='pdf-payload-injector',
    version='1.0.0',
    author='Security Research Team',
    author_email='security@example.com',
    description='Educational tool for PDF payload injection and vulnerability testing',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/pdf-payload-injector',
    project_urls={
        'Bug Reports': 'https://github.com/yourusername/pdf-payload-injector/issues',
        'Source': 'https://github.com/yourusername/pdf-payload-injector',
        'Documentation': 'https://github.com/yourusername/pdf-payload-injector/blob/main/pdf_payload_injector/README.md',
    },
    packages=find_packages(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Education',
        'Intended Audience :: Science/Research',
        'Topic :: Security',
        'Topic :: Education',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
        'Natural Language :: English',
    ],
    python_requires='>=3.8',
    install_requires=read_requirements(),
    entry_points={
        'console_scripts': [
            'pdf-injector=pdf_payload_injector.pdf_injector:main',
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords='pdf security payload injection vulnerability testing educational',
)