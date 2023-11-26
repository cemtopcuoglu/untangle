""" helper file """

SERVER_N = 13

class MyResponse:
    """ my response class """
    def __init__(self, before_mut, after_mut, mut_messages, seed, error_list,
                 false_list, true_list, http_0_9_list, too_long_list, zero_byte_list):
        """ initializing """
        self.before_mut = before_mut
        self.after_mut = after_mut
        self.mut_messages = mut_messages
        self.seed = seed
        self.error_list = error_list
        self.false_list = false_list
        self.true_list = true_list
        self.http_0_9_list = http_0_9_list
        self.too_long_list = too_long_list
        self.zero_byte_list = zero_byte_list
        self.mut = None
        self.responses = {}

        self.server_reaction_list = [None]*SERVER_N
