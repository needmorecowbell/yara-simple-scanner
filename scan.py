import yara

import os




def isMatch(rule, target_path):
    #rule = compiled yara rules
    m = rule.match(target_path)
    if m:
        return True
    else:
        return False


compiled_rules = []
target_path= 'target/'
rule_path = 'rules/'

def compileRules(rule_path):
    ruleSet=[]
    for root, sub, files in os.walk(rule_path):
        for file in files:
            print("\t"+os.path.join(root,file))
            rule = yara.compile(os.path.join(root,file))
            ruleSet.append(rule)
    return ruleSet


def scanTargetDirectory(target_path, ruleSet ):
    for root, sub, files in os.walk(target_path):
        for file in files: #check each file for rules
            print("\t"+os.path.join(root,file))
            for rule in ruleSet:
                if(isMatch(rule,os.path.join(root,file))):
                    matches = rule.match(os.path.join(root,file))
                    if(matches):
                        for match in matches:
                            print("\t\tYARA MATCH: "+ os.path.join(root,file)+"\t"+match.rule)

print("Loading rules")
ruleset = compileRules(rule_path)
print("Scanning Directory ...")
scanTargetDirectory(target_path, ruleset)
