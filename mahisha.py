'''
Author : Goutham Madhwaraj (@barriersec.com)
https://github.com/strikergoutham/Mahisha
'''
from flask import Flask, request
from flask_restful import Resource, Api
import calendar
import time
import os
import subprocess
import slack
import json
import requests
import platform
import configparser

config = configparser.ConfigParser()
config.read('config.conf')

app = Flask(__name__)
api = Api(app)

Mode = config['Properties']['Mode']
slack_token = os.getenv("SLACK_TOKEN")
GIT_TOKEN = os.getenv("GIT_TOKEN")
monitor_branch = config['Properties']['monitor_branch']
binary_path = config['Properties']['binary_path']
slack_channel = config['Properties']['slack_channel']
rulesPath = config['Properties']['gitleaks_RulesPath']
unique_json = []
osinfo = platform.system()
class ScanBranch(Resource):

    def AuditPR(self,url,resultpath,stderrpath,stdoutpath):

        print("Auditing PULL Request : ", url)
        if osinfo == "Windows":
                cmd3 = [binary_path,'/access-token',GIT_TOKEN, '/config', rulesPath, '/pr',
                    url, '/host', 'github', '/report', resultpath]
        else:
            cmd3 = [binary_path, '--access-token', GIT_TOKEN, '--config', rulesPath, '--pr',url, '--host', 'github', '--report', resultpath]

        with open(stdoutpath, "wb") as out, open(stderrpath, "wb") as err:
            p = subprocess.Popen(cmd3, stdout=out, stderr=err)
            p.wait()
        return

    def CompleteScan(self,repo_path,subBranch,resultpath,stdoutpath,stderrpath):

        print("Auditing Complete repository : ", repo_path)
        if osinfo == "Windows":
            cmd2 = [binary_path, '/config', rulesPath, '/repo', repo_path, '/branch',subBranch,'/access-token',GIT_TOKEN,'/report', resultpath]
        else:
            cmd2 = [binary_path, '--config', rulesPath, '--repo', repo_path, '--branch', subBranch,'--access-token',GIT_TOKEN,'--report', resultpath]

        with open(stdoutpath, "wb") as out, open(stderrpath, "wb") as err:
            p = subprocess.Popen(cmd2, stdout=out, stderr=err)
            p.wait()
        return


    def sendSlackMessage(self,resultpath):

        get_params = {"token": slack_token}
        user_data = requests.get(url='https://slack.com/api/users.list', params=get_params)
        user_data_json = json.loads(user_data.text)
        client = slack.WebClient(token=slack_token)
        with open(resultpath) as f:
            Json_Data = json.loads(f.read())
            for m in range(0, len(Json_Data)):
                generic_text = "*[+] Sensitive hardcoded credentials Found!*" + "\n"
                offend_text = "Offending Line : " + '`' + Json_Data[m]["line"] + '`' + "\n"
                rule_text = "Rule Name : " + '`' + Json_Data[m]["rule"] + '`' + "\n"
                repo_text = "Repository Name : " + '`' + Json_Data[m]["repo"] + '`' + "\n"
                file_text = "File Name : " + '`' + Json_Data[m]["file"] + '`' + "\n"
                commiter_name = "Author Name : " + '`' + Json_Data[m]["author"] + '`' + "\n"
                commiter_email = "Author Email : " + '`' + Json_Data[m]["email"] + '`' + "\n"
                commit_date = "Commit Date : " + '`' + Json_Data[m]["date"] + '`' + "\n"
                commit_message = "Commit Message : " + '`' + Json_Data[m]["commitMessage"] + '`' + "\n"
                commit_ID = "Commit ID : " + '`' + Json_Data[m]["commit"] + '`' + "\n"
                final_message = generic_text + offend_text + rule_text + repo_text + file_text + commiter_name + commiter_email + commit_date
                commit_email = Json_Data[m]["email"]
                response = client.chat_postMessage(channel=slack_channel, text=final_message)
        return

    def post(self):
        postdata = request.get_json()
        if "pusher" in postdata:
            reff_monitor = "refs/heads/"+monitor_branch
            if postdata["ref"] == reff_monitor:
                repo_path = "https://github.com/" + postdata["repository"]["full_name"]
                repo_name = postdata["repository"]["full_name"].split("/")[1]
                tempfolder = repo_name + "_" + "push"+"_"+ str(Mode) + str(calendar.timegm(time.gmtime()))
                cmd1 = "mkdir " + tempfolder
                os.system(cmd1)
                resultpath = tempfolder + '/resultsAuto.json'
                stderrpath = tempfolder + '/stderr.txt'
                stdoutpath = tempfolder + '/stdout.txt'
                ScanBranch.CompleteScan(self, repo_path, monitor_branch, resultpath, stdoutpath, stderrpath)
                if os.path.isfile(resultpath):
                    ScanBranch.sendSlackMessage(self,resultpath)
            return {'content':'Push Request'}

        if "action" in postdata:
            if postdata["action"] == "opened":
                refBranch = postdata["pull_request"]["base"]["ref"]
                if refBranch == monitor_branch:
                    pullReqURL = postdata["pull_request"]["url"]
                    subBranch = postdata["pull_request"]["head"]["ref"]
                    repositoryName = postdata["pull_request"]["head"]["repo"]["full_name"]
                    repo_name = repositoryName.split("/")[1]
                    tempfolder = repo_name + "_pull_" + str(Mode) + str(calendar.timegm(time.gmtime()))
                    cmd1 = "mkdir "+tempfolder
                    os.system(cmd1)
                    resultpath = tempfolder + '/resultsAuto.json'
                    stderrpath = tempfolder + '/stderr.txt'
                    stdoutpath = tempfolder + '/stdout.txt'
                    repo_path = 'https://github.com/' + repositoryName
                    if Mode == "1":
                        ScanBranch.AuditPR(self,pullReqURL,resultpath,stderrpath,stdoutpath)
                    else:
                        ScanBranch.CompleteScan(self,repo_path,subBranch,resultpath,stdoutpath,stderrpath)
                    if os.path.isfile(resultpath):
                        ScanBranch.sendSlackMessage(self,resultpath)


        return {'content':'Success'}


api.add_resource(ScanBranch, '/scanBranch')

if __name__ == "__main__":
    print('''
                   .__    .__       .__            
      _____ _____  |  |__ |__| _____|  |__ _____   
     /     \\__  \ |  |  \|  |/  ___/  |  \\__  \  
    |  Y Y  \/ __ \|   Y  \  |\___ \|   Y  \/ __ \_
    |__|_|  (____  /___|  /__/____  >___|  (____  /
          \/     \/     \/        \/     \/     \/ ''')
    app.run(threaded=True)
