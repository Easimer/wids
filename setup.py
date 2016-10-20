from setuptools import setup, find_packages

setup(
	name='easiwids',
	version='1.1.3',
	description='Wireless Intrusion Detection and Countermeasure System',
	author='Daniel Meszaros',
	author_email='easimer@gmail.com',
	license='GPLv2',
	classifiers = [
		'Development Status :: 5 - Production/Stable',
		'License :: OSI Approved :: GPLv2'],
	packages=['wids'],
	install_requires=['scapy-python3']
)