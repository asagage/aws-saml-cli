# aws-saml
This tool will authenticate into AWS using ADFS SAML. You 
should receive an authentication request on your phone, then after accepting 
will presented with a list of roles that you are authorized to assume. Choose 
the desired role.  You will then receive a set of temporary access keys and 
token for this role.  The credentials will be stored in `~/.aws/credentials`
under the 'saml' profile. You may then use any aws tools by passing the 
`--profile saml` option. 

You may pass the username with -u <username> or with an environment variable AWS_SAML_USERNAME.
If not passed, the script will prompt you for it.

You may also bypass the role list if you already know the index of the role
you wish to assume by passing the -r <index> parameter

# install
`pip install -r requirements.txt`

# usage
`python aws-saml.py`


## Set shell variables
If you would like to have the saml token directly set in your aws shell 
variables, you can create a bash alias function that will do this.
 
    $ vim ~/.bashrc
    
Go to the end of the file and a function like this:

    setSAMLToken() {
       # confirm path below is correct for your env
       if python ~/daws-saml-cli/aws-saml.py; then
          source ~/.aws/.token_file
          echo "Your creds have been set in your shell."
       fi
    }
    alias saml=setSAMLToken
 
Be sure to check the path to your aws-saml.py file and your tokenfile

Then you can just run the script from any bash prompt by just typing your alias:

    $ saml
    
