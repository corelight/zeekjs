# Extend the SSL::Info fields with ja3/ja3s fields.
redef record SSL::Info += {
  js_ja3: string &optional &log;
  js_ja3s: string &optional &log;
};

@load ./ja3.js
