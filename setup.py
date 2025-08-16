#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Site Arşivleyici Pro - Kurulum Dosyası
"""

from setuptools import setup, find_packages
import os

# README dosyasını oku
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Requirements dosyasını oku
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="web-site-arsivleyici-pro",
    version="2.0.0",
    author="Web Site Arşivleyici Pro Team",
    author_email="destek@example.com",
    description="Profesyonel web site arşivleme ve yedekleme çözümü",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/kullaniciadi/web-site-arsivleyici",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Internet :: WWW/HTTP :: Site Management",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: X11 Applications :: GTK",
        "Environment :: Win32 (MS Windows)",
        "Environment :: MacOS X",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "web-site-arsivleyici=main:main",
            "wsap=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.txt", "*.md", "*.rst", "*.yml", "*.yaml"],
    },
    keywords="web, site, archive, download, crawler, selenium, beautifulsoup",
    project_urls={
        "Bug Reports": "https://github.com/kullaniciadi/web-site-arsivleyici/issues",
        "Source": "https://github.com/kullaniciadi/web-site-arsivleyici",
        "Documentation": "https://github.com/kullaniciadi/web-site-arsivleyici/wiki",
    },
)
