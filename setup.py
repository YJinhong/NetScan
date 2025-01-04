from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="NetScan", 
    version="1.0.0", 
    author="YJinhong", 
    author_email="YJinhong222@gmail.com",  
    description="一个网络扫描工具",  
    long_description=long_description,  
    long_description_content_type="text/markdown", 
    url="https://github.com/YJinhong/NetScan.git", 
    packages=find_packages(),  
    classifiers=[ 
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",  
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8", 
    install_requires=[ 
        "tkinter",
        "ttkbootstrap",
        "requests",
        "scapy",
        "nmap",
    ],
    entry_points={  
        "console_scripts": [
            "netscan=NetScan:main",  
        ],
    },
)
