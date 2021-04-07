## Path traversal in Ruby's Tempfile and mktmpdir on Windows

### The bug

While playing around Ruby we noticed that Ruby's Tempfile/mktmpdir were allowing `\` in Filename and extension which immediately made us wonder what happens when we do this on windows as the file separator on Windows is also `\`. To our surprise, it was working, we had a path traversal in Tempfile on Windows. But to our knowledge while reading source of Node, generally languages have file separator based on the OS you're running the language on. So we wondered what is Ruby doing to identify file sepaator here. It didn't work on `File.basename` which made it clear that Tempfile is doing something differet.

### CVE-2018-6914 Patch analysis

A similar issue was previously reported by [@ooooooo_q](https://twitter.com/ooooooo_q) for Linux, where `/` could be used which made path traversal possible on both Linux and Windows. We looked at the patch of this bug, which was relatively straight forward, delete `/` (File::SEPARATOR) and `\` (File::ALT_SEPARATOR, set on windows only) from the input before creating the file.

```patch
--- lib/tmpdir.rb
+++ lib/tmpdir.rb
@@ -114,10 +114,12 @@ def create(basename, tmpdir=nil, max_try: nil, **opts)
       end
       n = nil
       prefix, suffix = basename
+      prefix = prefix.delete("#{File::SEPARATOR}#{File::ALT_SEPARATOR}")
       prefix = (String.try_convert(prefix) or
                 raise ArgumentError, "unexpected prefix: #{prefix.inspect}")
       suffix &&= (String.try_convert(suffix) or
                   raise ArgumentError, "unexpected suffix: #{suffix.inspect}")
+      suffix &&= suffix.delete("#{File::SEPARATOR}#{File::ALT_SEPARATOR}")
       begin
```

We run the above patch 

![image](https://user-images.githubusercontent.com/21000421/113866846-6c88ec00-97cb-11eb-8214-d2c6f7af8e2a.png)

The patch here works as expected, where's the problem? why is the `\` not removed from the input then? 

### Any changes that can regress this?

We opened the master branch and went through the code and found the code has recently changed, the change basically adds more characters and uses a constant now for this chars

```patch
---
 lib/tmpdir.rb | 6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

diff --git a/lib/tmpdir.rb b/lib/tmpdir.rb
index 87e53a8..05e74eb 100644
--- a/lib/tmpdir.rb
+++ b/lib/tmpdir.rb
@@ -112,6 +112,8 @@ def tmpdir
       Dir.tmpdir
     end
 
+    UNUSABLE_CHARS = [File::SEPARATOR, File::ALT_SEPARATOR, File::PATH_SEPARATOR, ":"].uniq.join("").freeze
+
     def create(basename, tmpdir=nil, max_try: nil, **opts)
       if $SAFE > 0 and tmpdir.tainted?
         tmpdir = '/tmp'
@@ -123,10 +125,10 @@ def create(basename, tmpdir=nil, max_try: nil, **opts)
       prefix, suffix = basename
       prefix = (String.try_convert(prefix) or
                 raise ArgumentError, "unexpected prefix: #{prefix.inspect}")
-      prefix = prefix.delete("#{File::SEPARATOR}#{File::ALT_SEPARATOR}")
+      prefix = prefix.delete(UNUSABLE_CHARS)
       suffix &&= (String.try_convert(suffix) or
                   raise ArgumentError, "unexpected suffix: #{suffix.inspect}")
-      suffix &&= suffix.delete("#{File::SEPARATOR}#{File::ALT_SEPARATOR}")
+      suffix &&= suffix.delete(UNUSABLE_CHARS)

```

Commit - https://github.com/ruby/tmpdir/commit/5a70e9c27d29ebcb7a04a6c00400219ac62ec0af

### What's wrong? why `\` is not deleted?

The change were basically same to us, until we tried them by ourself. 

![image](https://user-images.githubusercontent.com/21000421/113867036-a9ed7980-97cb-11eb-85b7-61f6d53d7bab.png)

Whoops, `.delete` expects `\` to be escaped, Was it intentional to write delete this way? or It's wrongly used here?

Ruby fixed it by changing the way delete has been used here - https://github.com/ruby/tmpdir/commit/adf294bc2d10cd223aa3ca488079ec313032c07b
HackerOne Report - https://hackerone.com/reports/1131465

That's all, Thanks for reading.
