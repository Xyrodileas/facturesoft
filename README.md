# facturesoft
FactureSoft

# Requirements
Automagie :
- Vagrant
- Ansible
- Virtualbox

Backend :
- Go installed and configure
- Some Go dependencies
- facturesoft-restapi

Frontend :
- Python3
- Django
- Some Django dependencies such as djang-bootstrap
- pip
- Some pip libraries
- facturesoft-frontend

# QuickStart

- Open a command-line interface into the FactureSoft folder located into the Vagrant folder.
- Type "vagrant up"
- Wait for Vagrant and Ansible to do their job
- Browse localhost:8000/front to access the application

# CODE
Logic -> facturesoft-frontend/front/view.py
Contain the logic to display for the different views.

Routes -> facturesoft-frontend/front/urls.py
Contain the differents routes to link an URL to a view.

View -> facturesoft-frontend/front/templates/*
The view are stored in the template directory.
They are HTML with Django's templating langage (To add variables/some logic).

# Automatisation

Vagrant is responsible to provision the required ressource and his network configuration, and call Ansible to manage the configuration of the ressource
Specs :
- Debian 64bits
- Portforwarding on 1321 (backend) and 8000 (frontend)
- ssh enable, possible to ssh into the machine with the command vagrant ssh

Ansible is responsible to manage the configuration of the allocated ressource.
Ansible will do the following:
- Install and configure Go
- Set up the dependency for the backend
- Copy and setup the backend in go
- Install Python3 and Django
- Set up the dependency for the frontend
- Install and setup the frontend
- Start the backend and the frontend in their own screen

