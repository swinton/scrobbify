scrobbify - A Python library providing real-time 'now playing notifications' for Spotify
=========================================================================================

Usage
-----
1. Install scrobbify from the Python Package Index, e.g. using easy_install:

        $ easy_install scrobbify

2. Be sure to [enable scrobbling to last.fm](http://www.spotify.com/uk/blog/archives/2008/12/18/spotify-scrobbles/) in your Spotify player preferences.

3. Use scrobbify like so:

        import scrobbify, sys
        
        def cb(now_playing, data):
            sys.stdout.write("Now playing: '%s' by '%s'.\n" % (now_playing['t'][0], now_playing['a'][0]))
            sys.stdout.flush()
            
        scrobbifier = scrobbify.Scrobbify(cb, interface='en0')
        scrobbifier.start()
        
        # Exit gracefully...
        try:
            while True:
                time.sleep(2**20)
        except (KeyboardInterrupt, SystemExit):
            scrob.stop()
            
        
About
-----
There's a notable lack of [AppleScript support in the Spotify player](http://getsatisfaction.com/spotify/topics/spotify_applescript_dictionary), and I (along [with many others](http://getsatisfaction.com/spotify/topics/spotify_applescript_dictionary)) would like to do interesting things with Spotify. Things like, updating my [Adium](http://adium.im/) status with what I'm listening to on Spotify, sticking what's now playing in the office on an LED message panel, and doing other interesting mashups.

So, here's a workaround, using Spotify's built-in [scrobbling](http://www.last.fm/help/faq?category=Scrobbling) feature. What I'm attempting to do, is capture the network packets that are sent from the Spotify player to Last.fm's [API](http://www.last.fm/api/intro), and extract what's now playing by inspecting the HTTP request.

Yep, it's all pretty backwards, but I think it's the only viable workaround, until either Spotify adds an AppleScript dictionary, or Last.fm provides some kind of real-time webhook interface.

Feedback
--------
I'm fairly certain the code is sub-optimal right now, so feel free to leave me some feedback, via [email](http://scr.im/stevie) or even [twitter](http://twitter.com/steveWINton). :)

