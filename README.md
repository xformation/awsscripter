=======
awsscripter
=======

About
-----

awsscripter is a tool to write automation on the top of  AWS CLI (Boto).It automates away some of the more mundane, repetitive and error-prone tasks, simplify aws resource management more efficiently.

Features:
- Audit AWS accounts with different compliance program such as CISP, PCI-DSS, HIPPA
- Takes inputs from templates & Configuration and performs user friendly automations by combining aws boto api's
- Support for inserting dynamic values in templates via customisable resolvers
- Support for running arbitrary code as hooks before/after stack builds
- Support for templates written in JSON, YAML, Jinja2 or Python DSLs such as Troposphere
- Easy integration to xformnation platform
- Fast, highly parallel builds
- Built in support for working with ALM (application lifecycle Management tools and Operation Support System
- Infrastructure visibility with meta-operations such as stack querying protection

Example
-------
    command: awsscripter audit
  Commands for auditing aws environment with awsscripter. This will iclude
  CISP/ PCIDSS/ HIPPA Audit.

    Usage: awsscripter [OPTIONS] COMMAND [ARGS]...
    
      awsscripter is a tool to manage your cloud native infrastructure
      deployments.
    
    Options:
      --version             Show the version and exit.
      --debug               Turn on debug logging.
      --dir TEXT            Specify awsscripter directory.
      --output [yaml|json]  The formatting style for command output.
      --no-colour           Turn off output colouring.
      --var TEXT            A variable to template into config files.
      --var-file FILENAME   A YAML file of variables to template into config
                            files.
      --help                Show this message and exit.
    
    Commands:
      audit        Commands for auditing aws environment with...
      init         Commands for initialising awsscripter...
      list         packet security check :return:
      monitor      Commands for auditing aws environment with...
      security     packet security check :return:
      stack        Commands for auditing aws environment with...
      testcommand  A sample testcommand
	sub-commands:
		#awsscripter stack
			Usage: awsscripter stack [OPTIONS] COMMAND [ARGS]...
			Options:
			  --help  Show this message and exit.

			Commands:
			  create      Creates a stack or a change set.
			  delete      Deletes a stack or a change set.
			  describe    Commands for describing attributes of stacks.
			  execute     Executes a change set.
			  generate    Prints the template.
			  launch      Launch a stack or environment.
			  list        Commands for listing attributes of stacks.
			  set-policy  Sets stack policy.
			  status      Print status of stack or environment.
			  update      Update a stack.
			  validate    Validates the template.
		#awsscripter init
			Usage: awsscripter init [OPTIONS] COMMAND [ARGS]...

			  Commands for initialising awsscripter projects.

			Options:
			  --help  Show this message and exit.

			Commands:
			  env      Initialises an environment in a project.
			  project  Initialises a new project.

Python:

.. code-block:: python

Install
-------

::

  $ pip install awsscripter

More information on installing awsscripter can be found in our `Installation Guide .


Tutorial and Documentation
--------------------------



Contributions
-------------

See our `Contributing Guide <CONTRIBUTING.rst>`_.

