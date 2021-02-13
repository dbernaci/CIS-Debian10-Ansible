#Get extra log when running playbook with debuging
ansible-playbook -i host run.yaml  -vvvv

#Run one tag only
ansible-playbook -i host run.yaml --tags="1.1.21"

#Skips tags
ansible-playbook -i host run.yaml --skip-tags="3.1.2" --skip-tags="2.3.5"


