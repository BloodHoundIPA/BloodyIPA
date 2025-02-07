import io
import os
import setuptools
from bloodyipa.config import VERSION

current_dir = os.path.abspath(os.path.dirname(__file__))

with io.open(os.path.join(current_dir, "README.md"), encoding="utf-8") as fd:
    desc = fd.read()

with io.open(os.path.join(current_dir, "requirements.txt"), encoding="utf-8") as fd:
    requirements = [line.strip() for line in fd.readlines()]

setuptools.setup(
    name="bloodyipa",
    version=VERSION,
    description="FreeIPA python collector",
    long_description=desc,
    long_description_content_type="text/markdown",
    url="https://github.com/BloodHoundIPA/BloodyIPA",
    packages=setuptools.find_packages(),
    install_requires=requirements,
    python_requires=">=3.10",
    entry_points={
        'console_scripts': [
            'bloodyipa = bloodyipa.__main__:main'
        ]
    },
    classifiers=[
        "Programming Language :: Python",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
    ],
    keywords=['freeipa', 'ldap', 'http', 'pentesting', 'security', 'bloodhound', 'bloodhoundipa']
)
