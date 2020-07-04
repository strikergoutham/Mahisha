# Mahisha
Mahisha is a real time monitoring tool for accidental commit of sensitive secrets on github. Its a wrapper webservice which uses gitleaks to audit for secrets in real time.

![Mahisha](/screenshots/mahisha_2.PNG)

## Overview

> Mahisha makes use of gitleaks to audit secrets in real time. it makes use of combination of webhook and slack integration to make blue teamer's / internal security engineer's job easy in detecting sensitive secrets at earlier stages of code commit.

> Monitor secrets for a particular release/specific branch.

> Triggers on Pull Request and Push Github Events.

> Pull Request trigger with multiple modes. Either Audit only PR merge request or complete branch for secrets.

> Slack integration for real time notification of results.

## Steps to Setup up Mahisha :

Mahisha uses python's flask for hosting the web service. The webservice endpoint ( httpsx://server/ScanBranch ) is exposed and is used as webhook url for github events(push,pull request) for real time consumption of data.

### Prerequisites :

>> Requires Python 3

>> Runs on both Windows / Linux .

>> install dependencies :
```bash
pip3 install -r requirements.txt
```

### Steps:

>> Generate **github API token** for the account which has the code repositories accessibe.

>> Create a slack channel and generate **slack user token** with privileges of posting messages accross workspace.

>> Get the latest binary version of gitleaks from the https://github.com/zricethezav/gitleaks/releases

>> define the regex patterns which you want to use to detect secrets, Detailed usage of gitleaks can be found here : https://github.com/zricethezav/gitleaks/wiki

>> On the server, edit the **config.conf** with the required values such as gitleaks binary location, rules file location , Audit Mode for Pull request trigger,slack channel name that you would like to send notification.

Example config:

```bash
[Properties]
monitor_branch = master
binary_path = /root/Desktop/secrets/gitleaks
slack_channel = #gitleaks-alerts
Mode = 1
gitleaks_RulesPath = rules.toml
```
        
#### Here Mode can take two values 1 or 2. 
                             #### Mode = 1 #Audit only PR for the raised PR request.
                             #### Mode = 2 #Audit Complete branch for which PR is raised for.

#### Monitor_branch takes up value of the branch that you would like to monitor. Default is master branch.

>> Start the server
```bash
python3 mahisha.py
```
>> Select the Repositories you would like to monitor and set up web hooks in the repository settings for PUSH and Pull Request Events.

>> You are all set up! Check Mahisha in action for all further activities on the monitored repository.

Mahisha Receives the webhook data, proccess and audit the code for secrets using gitleaks and finally forwards the formatted result to the specified slack channel.
![Mahisha](/screenshots/mahisha_3.PNG)
##### Developed with ♥️ by: Goutham Madhwaraj
##### Do not use this tool for any malicious purpose. I am not responsible for any damage you cause / any non desirable consequences with the help of this tool.

