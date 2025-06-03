import Guacamole from 'guacamole-common-js';

const clipboard = {};

clipboard.install = (client) => {
  // Don't automatically try to read clipboard on load - wait for user interaction
  window.addEventListener('copy', () => clipboard.update(client)());
  window.addEventListener('cut', () => clipboard.update(client)());
  window.addEventListener('focus', e => {
    if (e.target === window) {
      // Only try clipboard operations after user interaction
      if (document.hasFocus()) {
        clipboard.update(client)();
      }
    }
  }, true);
};

clipboard.update = client => {
  return () => {
    clipboard.getLocalClipboard()
      .then(data => {
        if (data) {
          clipboard.cache = data;
          clipboard.setRemoteClipboard(client);
        }
      })
      .catch(err => {
        // Silently handle clipboard permission errors
        console.debug('Clipboard access not permitted:', err);
      });
  };
};

clipboard.setRemoteClipboard = (client) => {
  if (!clipboard.cache) {
    return;
  }

  let writer;

  const stream = client.createClipboardStream(clipboard.cache.type);

  if (typeof clipboard.cache.data === 'string') {
    writer = new Guacamole.StringWriter(stream);
    writer.sendText(clipboard.cache.data);
    writer.sendEnd();
  } else {
    writer = new Guacamole.BlobWriter(stream);
    writer.oncomplete = function clipboardSent() {
      writer.sendEnd();
    };
    writer.sendBlob(clipboard.cache.data);
  }
};

clipboard.getLocalClipboard = async () => {
  try {
    if (navigator.clipboard && navigator.clipboard.readText) {
      const text = await navigator.clipboard.readText();
      return {
        type: 'text/plain',
        data: text
      };
    }
  } catch (error) {
    // Return null instead of failing if clipboard permission is denied
    return null;
  }
};

clipboard.setLocalClipboard = async (data) => {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      if (data.type === 'text/plain') {
        await navigator.clipboard.writeText(data.data);
      }
    }
  } catch (error) {
    console.debug('Could not write to clipboard:', error);
  }
};

clipboard.onClipboard = (stream, mimetype) => {
  let reader;

  if (/^text\//.exec(mimetype)) {
    reader = new Guacamole.StringReader(stream);

    // Assemble received data into a single string
    let data = '';
    reader.ontext = text => {
      data += text;
    };

    // Set clipboard contents once stream is finished
    reader.onend = () => {
      clipboard.setLocalClipboard({
        type: mimetype,
        data: data
      });
    };
  } else {
    reader = new Guacamole.BlobReader(stream, mimetype);
    reader.onend = () => {
      clipboard.setLocalClipboard({
        type: mimetype,
        data: reader.getBlob()
      });
    };
  }
};

export default clipboard;