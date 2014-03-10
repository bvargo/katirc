# IRC Gateway for [Katō](https://kato.im/)

KatIRC is an IRC gateway for Katō. This means that you can use your own IRC
client. KatIRC will translate IRC commands from your client into Katō API
calls and vice versa.

Note that this is alpha quality software, at best. It was a quick hack
project, not production quality software, although the author does use it
almost every day.

## Requirements

Exact versions are documented in `requirements.txt` so they should
only be a virtualenv and

    pip install

away. If installing manually, you'll need:

- Python 2
- [Twisted](http://www.twistedmatrix.com/). Ensure that twisted-words is
  included.
- [AutoBahn 0.6.x](http://autobahn.ws/python/)

## Usage

1. Start the server.

    ```
    ./main.py
    ```

    This starts the server on localhost, port 6667 (IRC).

2. Configure your IRC client.
    - Host: localhost
    - Nick: Any nick you would like
    - IRC Password: Your Katō username and password, separated by a space.

    Example irssi configuration:

    ```
    servers = (
      {
        address = "localhost";
        chatnet = "katirc";
        port = "6667";
        password = "kato.user@example.com my_kato_password";
        autoconnect = "yes";
      }
    );
    ```

3. Start your client.

    Upon successful login, the server will list available Katō rooms and the
    associated IRC channel names.

## Notable Differences from the Katō Client

- In Katō, if someone mentions you in any room, then you get a notification,
  even if you are not in the room. With KatIRC, you only get messages for
  channels that you have joined, even if you are mentioned in another room.

## Mention Support

In Katō, you mention people with @User. In KatIRC, just use the IRC nick, like
you would in any IRC channel. KatIRC automatically translates between Katō
mentions and IRC nicknames, which most clients will treat as a mention.

In order to prevent false matches, such as in URLs, the nickname must be
proceeded by a space (or be the first word) and  must be followed by a
punctuation character (or be the last word). In addition, a proceeding @
character, e.g. @nick, is allowed, and will be converted automatically.

@Everybody mentions are not supported at the moment.

## Missing Features

Just about everything that is not basic chat is not supported. This includes:

- User status information (present, away, offline). For the moment, you will
  show up as offline to all other users.
- @Everybody mentions
- Email notifications for offline users.
- Multi-organization support
- Creating new chat rooms
- Chat room renames / rooms added while logged in
- User additions while logged in
- User typing indicators
- Lots of other stuff
