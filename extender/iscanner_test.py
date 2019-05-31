from burp import IBurpExtender
from burp import IScannerCheck
from java.io import PrintWriter


class BurpExtender(IBurpExtender, IScannerCheck):
    
    #
    # implement IBurpExtender
    #
    def    registerExtenderCallbacks(self, callbacks):
        # set our extension name
        callbacks.setExtensionName("passive scanner")
        
        # obtain our output stream
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        
        # obtain an extension helpers object
        self.helpers = callbacks.getHelpers()


    #
    # implement IScannerCheck
    #
    def doPassiveScan(self, baseRequestResponse):
        self.stdout.println('oh! boy. this can be it!')
        return None
        
        
    