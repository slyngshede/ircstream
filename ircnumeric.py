# IRC numeric table
#
# Based on IRC Definition files, https://defs.ircdocs.horse/
# Revision 1.62

from enum import Enum


class IRCNumeric(Enum):
    """Base class for IRC numeric enums"""

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}_{self.name}"


class RPL(IRCNumeric):
    """Standard IRC RPL_* replies, as defined in RFCs"""

    WELCOME = "001"
    YOURHOST = "002"
    CREATED = "003"
    MYINFO = "004"
    ISUPPORT = "005"
    UMODEIS = "221"
    WHOISUSER = "311"
    WHOISSERVER = "312"
    ENDOFWHO = "315"
    WHOISIDLE = "317"
    ENDOFWHOIS = "318"
    LIST = "322"
    LISTEND = "323"
    CHANNELMODEIS = "324"
    TOPIC = "332"
    TOPICWHOTIME = "333"
    NAMREPLY = "353"
    ENDOFNAMES = "366"
    ENDOFBANLIST = "368"
    MOTD = "372"
    MOTDSTART = "375"
    ENDOFMOTD = "376"


class ERR(IRCNumeric):
    """Erroneous IRC ERR_* replies, as defined in RFCs"""

    NOSUCHNICK = "401"
    NOSUCHCHANNEL = "403"
    CANNOTSENDTOCHAN = "404"
    NOORIGIN = "409"
    UNKNOWNCOMMAND = "421"
    NONICKNAMEGIVEN = "431"
    ERRONEUSNICKNAME = "432"
    NOTONCHANNEL = "442"
    NOTREGISTERED = "451"
    NEEDMOREPARAMS = "461"
    ALREADYREGISTERED = "462"
    CHANOPRIVSNEEDED = "482"
    UMODEUNKNOWNFLAG = "501"
    USERSDONTMATCH = "502"
