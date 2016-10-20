from setuptools import setup, find_packages

setup(
	name='easiwidsd',
	version='1.0.0',
	description='Wireless Intrusion Detection and Countermeasure System Server',
	author='Daniel Meszaros',
	author_email='easimer@gmail.com',
	license='GPLv2',
	classifiers = [
		'Development Status :: 5 - Production/Stable',
		'License :: OSI Approved :: GPLv2'],
	packages=['widsd'],
)