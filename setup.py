from setuptools import setup, find_packages

setup(
        name='wwwtools',
        version='0.1.15',
        description='Collection of tools for exploring and analyzing the web',
        url='https://github.com/tempelkim/wwwtools',
        author='Boris Kimmina',
        author_email='kim@kimmina.net',
        license='MIT',
        packages=['wwwtools'],
        install_requires=[
            'httplib2',
            'python-dateutil',
            'geoip2',
            'maxminddb-geolite2',
            'requests',
            'SSLyze',
        ],
        zip_safe=False
)
