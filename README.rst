wsgir
=====

A clone of `Flaskr <http://flask.pocoo.org/docs/0.12/tutorial/introduction/>`_
without `Flask <http://flask.pocoo.org/>`_ or other external dependencies.

It is intended to be a good example to explain how difficult to construct a
robust web application from scratch.


Dependencies
------------

- Python 2.7


Install
-------

.. code::

  git clone https://github.com/manicmaniac/wsgir.git
  python setup.py install


Usage
-----

.. code::

  python -m wsgir initdb
  python -m wsgir run

Then open a browser and visit http://localhost:5000.


Testing
-------

.. code::

   python -m unittest discover


License
-------

The MIT license.
