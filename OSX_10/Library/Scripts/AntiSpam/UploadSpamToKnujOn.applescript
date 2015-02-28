--
--  Copyright (c) 2014,2015 T. R. Burghart
--
--  Permission to use, copy, modify, and/or distribute this software for any
--  purpose with or without fee is hereby granted, provided that the above
--  copyright notice and this permission notice appear in all copies.
--
--  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
--  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
--  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
--  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
--  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
--  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
--  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
--

--
-- Send everything in the Junk Mailbox that is marked 'read' to KnujOn
-- In addition, KnujOn forwards messages to the FTC
--
-- Messages that haven't been marked 'read' will be left where they are
-- for future review.  Because of the nature of the reporting, you really
-- don't want any legitimate mail (whether unwanted or otherwise) getting
-- reported as spam, hence the requirement that you mark it 'read' first.
--
-- Save this file as "Report Spam to KnujOn.scpt", or whatever name you
-- like, under ~/Library/Scripts (for that user) or /Library/Scripts (for
-- all users) and enable the Scripts menu in AppleScript Editor Preferences.
--
-- Alternately, you can save it as an Application that can be run directly
-- and place it in your /Applications folder.  Either AppleScript Editor
-- or 'osacompile' can be used for this, but I'm not going to provide a
-- tutorial here.
--

--	
-- Replace this with your KnujOn ID if you have one
--	it's something like xx##### as of this writing
--
property KNUJON_ID : "nonreg"

--
-- It's MUCH more reliable, and faster, to copy messages from remote
-- servers' junk mail folders to a local folder as an intermediate step.
-- Use whatever you like, just as long as you create it under 'On My Mac'
-- If it doesn't exist, it will be created.
-- NOTE: Files in the staging directory are assumed to have already been
-- reviewed and are not tested for 'read' or 'junk' status.
--
property STAGING_MB : "Local Junk Upload Staging"

--
-- Where to upload, and the fields required (a sequence of NV pairs).
-- Minor changes to where and how KnujOn accepts bulk uploads should be
-- relatively easy to accomodate here.  If there are significant changes
-- then other script modifications may be necessary.
--
property UPLOAD_TO : "http://www.knujon.com/uploadjunk.php"
property FORM_FIELDS : {{name:"idname", value:KNUJON_ID}}

--
-- The working directory name needs to be unique, so other processes
-- don't use it, but Mail chokes on some of the actions often enough
-- that it's desirable to be able to pick up where we left off, so make it
-- durable.  A UUID serves this purpose nicely.
-- The script cleans it out on success, so it can be safely reused.
--
-- If you're paranoid and want a different working directory UUID,
-- execute this in Terminal:
--	/usr/bin/uuidgen | /usr/bin/tr '[:upper:]' '[:lower:]'
-- and copy/paste the result into the string below.
-- Or just use whatever you want.
--
property WORK_UUID : "449f955a-5492-4b1e-bead-ef6575202cdb"
--
-- Use a path in the system, rather than user, temp directory for
-- durability, with the understanding that it'll get wiped whenever
-- the system is rebooted.
-- By incorporating the User ID, the name remains distinct per user,
-- without different people on multi-user machines using each others
-- directories.  Note that this is set each time the script is run so that
-- the UserID is that of the user running the script - if you use a script
-- property, it'll only be reset when the script is compiled, and everyone
-- may get the same name depending on whether the script is stored
-- in a shared location.
--
on WorkPath()
	-- (user ID of (system info)) isn't reliable when run from the script menu
	set suffix to (do shell script "/usr/bin/id -u")
	return "/tmp/spam." & WORK_UUID & "." & suffix
end WorkPath

--
-- a couple of constants
--
property MESG_DIR : "msgs"
property MESG_EXT : ".txt"
property PATH_SEP : "/"

on run
	set msg_count to missing value
	set work_path to missing value
	
	tell application "Mail"
		launch
		try
			set work_mail to mailbox STAGING_MB
		on error
			set work_mail to make new mailbox with properties {name:STAGING_MB}
		end try
		
		if (count of messages of junk mailbox) is greater than 0 then
			set junk_messages to messages of junk mailbox
			repeat with cur_msg in junk_messages
				--
				-- Depending on where the message actually resides, network status,
				-- server maintenance, fetch interval, and a number of other possible
				-- glitches, this can fail.  If it does, just ignore it and assume we'll
				-- pick it up on some subsequent run.
				--
				try
					if deleted status of cur_msg is false and read status of cur_msg is true then
						set junk mail status of cur_msg to true
						move cur_msg to work_mail
					end if
				end try
			end repeat
		end if
		
		set work_path to my WorkPath()
		set msg_count to my GetWorkCount(work_path)
		if msg_count is 0 and (count of messages of work_mail) is 0 then
			my DisplayResult(0)
			return
		end if
		
		set mesg_path to work_path & PATH_SEP & MESG_DIR & PATH_SEP
		set junk_messages to messages of work_mail
		repeat with cur_msg in junk_messages
			try
				if deleted status of cur_msg is false then
					set msg_id to (id of cur_msg as string)
					set out_data to source of cur_msg
					set msg_file to mesg_path & msg_id & MESG_EXT
					set io_err to missing value
					tell current application
						set out_file to open for access msg_file with write permission
						try
							write out_data to out_file
							set msg_count to (msg_count + 1)
						on error et
							set io_err to et
						end try
						close access out_file
					end tell
					if io_err is not equal to missing value then
						display alert "Unable to write message " & msg_id & linefeed & io_err as warning
					else
						delete cur_msg
					end if
				end if
			end try
		end repeat
	end tell
	
	if msg_count is greater than 0 then
		set msg_count to (do shell script GenerateScript(work_path))
	end if
	DisplayResult(msg_count)
end run

on DisplayResult(msg_count)
	if (msg_count as integer) is equal to 0 then
		set msg to "No eligible spam messages were found."
	else if (msg_count as integer) is equal to 1 then
		set msg to "1 message was uploaded to KnujOn."
	else
		set msg to (msg_count as text) & " messages were uploaded to KnujOn."
	end if
	display dialog msg buttons {"OK"} default button 1 with title "Upload Spam" with icon note
end DisplayResult

on GetWorkCount(work_path)
	set mesg_path to work_path & PATH_SEP & MESG_DIR
	set cnt to 0
	tell application "System Events"
		set dir to missing value
		try
			set dir to folder work_path
			try
				set dir to folder mesg_path
				set cnt to (count of files of dir)
			on error
				make new folder with properties {name:mesg_path}
			end try
		on error
			make new folder with properties {name:work_path}
			make new folder with properties {name:mesg_path}
		end try
	end tell
	return cnt
end GetWorkCount

--
-- text constants used in the script for readability
--
property BQ : "`"
property BS : "\\"
property DQ : quote
property EQ : "="
property LF : linefeed
property SP : space
property SQ : "'"

on GenerateScript(work_path)
	set spam_file to KNUJON_ID & ".zip"
	set script_path to work_path & PATH_SEP & "upload.sh"
	--
	-- Generate the script in a variable before opening the file in case
	-- a change somewhere (like the form fields) causes an error.
	-- The AppleScript editor is not accomodating when it comes to
	-- open file descriptors, and the I/O is more efficient in a single
	-- write anyway.
	--
	-- The script will be run in the system shell (/bin/sh), so there's
	-- no need to specify it.
	set scr to {}
	-- Make sure we exit on any error, so that
	-- a subsequent run will pick up where it failed
	set end of scr to "set -e" & LF
	
	-- all locations are relative to the work directory
	set end of scr to "cd" & SP & quoted form of work_path & LF
	
	-- create the archive, recording the number of files in 'cnt'
	set end of scr to "cnt" & EQ & BQ & "/usr/bin/zip -rDjX"
	set end of scr to SP & quoted form of spam_file
	set end of scr to SP & quoted form of MESG_DIR
	set end of scr to SP & "-i" & SP & SQ & "*" & MESG_EXT & SQ
	set end of scr to " | /usr/bin/wc -l" & BQ & LF
	
	-- upload it to KnujOn
	set end of scr to "/usr/bin/curl --silent --output /dev/null --stderr /dev/null"
	set end of scr to SP & "--form" & SP & SQ & "uploadedfile=@" & spam_file & SQ
	repeat with fld in FORM_FIELDS
		set end of scr to SP & "--form" & SP & SQ & (name of fld) & EQ & (value of fld) & SQ
	end repeat
	set end of scr to SP & quoted form of UPLOAD_TO & LF
	
	-- if we get this far, the messages have been successfully uploaded
	-- clean up so these messages won't get uploaded again
	set end of scr to "/bin/rm -rf" & SP & quoted form of spam_file
	set end of scr to SP & quoted form of MESG_DIR & LF
	
	-- report the number uploaded
	set end of scr to "echo $cnt" & LF
	
	-- write the script, creating or truncating as needed
	set fd to open for access script_path with write permission
	set eof fd to 0
	write (scr as text) to fd
	close access fd
	-- make it executable
	do shell script "/bin/chmod 750" & SP & quoted form of script_path
	
	return script_path
end GenerateScript
