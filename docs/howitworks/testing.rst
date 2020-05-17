Automated Tests
===============

Geneva has a system of automated tests in the :code:`tests/` directory, powered by pytest. Unless you are doing
modifications to the source code, you can generally ignore these. 

If you need to run them yourself, you can do so with: 

.. code-block:: none

    # python3 -m pytest -sv tests/

To put the tests in debug mode, you can add :code:`--evolve-logger debug`. 
