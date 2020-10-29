class PocBase():

    def check_rule(self,dictdata,require):
        '''
        check the rule is right
        '''
        if require.get("type","tcp") != dictdata.get("type",None):
            return False
        result=False
        for dict_service in dictdata.get("service").keys():
            if result:
                return True
            for require_service in require.get("service"):
                if dict_service.lower() in require_service.lower():
                    result=True
                    break
        return result