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
-- The first time it's run by each user it will prompt for a couple of
-- needed valuses, then it will never ask again.
--

--
-- A few shared constants
--
property APP_DOMAIN : "net.tedb.antispam.knujon"
property APP_REV_TS : current date
property NON : ""
property PATH_SEP : "/"

on run
	set tmp to GetAppProperties()
	
	set msg_cnt to 0
	set msg_dir to mesgpath of tmp
	set msg_ext to mesgext of tmp
	set stagemb to stagemb of tmp
	set ul_exec to ulscript of tmp
	
	tell application "Mail"
		launch
		set stagemb to mailbox stagemb
		
		if (count of messages of junk mailbox) > 0 then
			set junk_msgs to messages of junk mailbox
			repeat with cur_msg in junk_msgs
				--
				-- Depending on where the message actually resides, network status,
				-- server maintenance, fetch interval, and a number of other possible
				-- glitches, this can fail.  If it does, just ignore it and assume we'll
				-- pick it up on some subsequent run.
				--
				try
					if deleted status of cur_msg is false and read status of cur_msg is true then
						set junk mail status of cur_msg to true
						move cur_msg to stagemb
					end if
				end try
			end repeat
		end if
		
		set junk_msgs to messages of stagemb
		if (count of junk_msgs) = 0 then
			tell current application
				set msg_cnt to (do shell script "/usr/bin/find " & quoted form of msg_dir & " -type f -name '*" & msg_ext & "' | /usr/bin/wc -l") as integer
			end tell
			if msg_cnt = 0 then
				my DisplayResult(0)
				return
			end if
		else
			set msg_path to msg_dir & PATH_SEP
			repeat with cur_msg in junk_msgs
				try
					if deleted status of cur_msg is false then
						set msg_id to (id of cur_msg as string)
						set out_data to source of cur_msg
						set msg_file to msg_path & msg_id & msg_ext
						set io_err to missing value
						tell current application
							set out_file to open for access msg_file with write permission
							try
								write out_data to out_file
								set msg_cnt to (msg_cnt + 1)
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
		end if
	end tell
	if msg_cnt > 0 then
		set msg_cnt to (do shell script ul_exec) as integer
	end if
	DisplayResult(msg_cnt)
end run

--
-- File Type returned from GetOsPathType
--
property FT_DIRECTORY : "Directory"
property FT_REGULAR : "Regular File"
property FT_SYMLINK : "Symbolic Link"
--
-- Modes for Filesystem entities we use *as strings*
--
property FM_EXECFILE : "700"
property FM_MESGPATH : "700"
property FM_WORKPATH : "700"

--
-- Constants used in the application
--
property DEF_KNUJONID : "nonreg"
property DEF_STAGEMB_NAME : "Local Junk Upload Staging"
property EXEC_FILE_NAME : "/upload.sh"
property KEY_APP_REV_TS : "AppRevision"
property KEY_EXECFILE_HASH : "VHash1"
property KEY_EXECPATH_HASH : "VHash2"
property KEY_KNUJONID_HASH : "VHash3"
property KEY_KNUJONID_VAL : "KnujOnId"
property KEY_MESGPATH_HASH : "VHash4"
property KEY_STAGEMB_HASH : "VHash5"
property KEY_STAGEMB_VAL : "StagingMB"
property KEY_WORKPATH_HASH : "VHash6"
property KEY_WORKPATH_VAL : "WorkPath"
property MESG_DIR_NAME : "/msgs"
property MESG_FILE_EXT : ".txt"
property PLIST_FILE_EXT : ".plist"

--
-- returns a record containing:
--
--	mesgext:  "email message file extension (including leading period)"
--	mesgpath: "posix path to the messages directory"
--	ulscript: "posix path to the upload script"
--  stagemb:  "name of the junk staging mailbox within Apple mail"
--
on GetAppProperties()
	set plist_file to POSIX path of ((path to preferences as string) & APP_DOMAIN & PLIST_FILE_EXT)
	
	set all_hashes_pass to (GetPListValue(plist_file, KEY_APP_REV_TS) is APP_REV_TS)
	if not all_hashes_pass then
		SetPListValue(plist_file, KEY_APP_REV_TS, date, APP_REV_TS)
	end if
	--
	-- check for the id first, as it can short-curcuit later ops
	--
	set knujon_id to GetPListValue(plist_file, KEY_KNUJONID_VAL)
	if knujon_id is not missing value then
		set all_hashes_pass to HashesMatch(all_hashes_pass, knujon_id, plist_file, KEY_KNUJONID_HASH)
	else
		-- get it from the user
		set knujon_id to GetUserId()
		set all_hashes_pass to false
		SetPListValue(plist_file, KEY_KNUJONID_VAL, string, knujon_id)
		SetPListValue(plist_file, KEY_KNUJONID_HASH, string, GetStringHash(knujon_id))
	end if
	--
	-- get the name of the staging mailbox
	-- this doesn't necessarily matter to the upload script, but its
	-- hash is tracked in case it ever does
	--
	set stage_mb to GetPListValue(plist_file, KEY_STAGEMB_VAL)
	if stage_mb is not missing value then
		set tmp to HashesMatch(true, stage_mb, plist_file, KEY_STAGEMB_HASH)
		if not tmp then
			--	the PList has been edited ...
			set all_hashes_pass to false
			set check to ValidateLocalMailbox(stage_mb)
			if ok of check then
				if stage_mb is not data of check then
					set stage_mb to data of check
					SetPListValue(plist_file, KEY_STAGEMB_VAL, string, stage_mb)
					SetPListValue(plist_file, KEY_STAGEMB_HASH, string, GetStringHash(stage_mb))
				end if
			else
				--	... and the edit is invalid!
				set stage_mb to missing value
			end if
		end if
	end if
	if stage_mb is missing value then
		-- get it from the user
		set stage_mb to GetStagingMB()
		set all_hashes_pass to false
		SetPListValue(plist_file, KEY_STAGEMB_VAL, string, stage_mb)
		SetPListValue(plist_file, KEY_STAGEMB_HASH, string, GetStringHash(stage_mb))
	end if
	--
	-- no work_path means nothing's set up
	--
	set work_path to GetPListValue(plist_file, KEY_WORKPATH_VAL)
	if work_path is not missing value then
		set tgt_info to GetPathInfo(work_path)
		if tgt_info is missing value then
			set par_info to GetPathInfo(GetPathDirname(work_path))
			if par_info is missing value or kind of par_info is not FT_DIRECTORY then
				set work_path to missing value
			else
				CreateDirectory(work_path, FM_WORKPATH)
				set all_hashes_pass to HashesMatch(all_hashes_pass, work_path, plist_file, KEY_WORKPATH_HASH)
			end if
		else if kind of tgt_info is FT_DIRECTORY then
			if perms of tgt_info is not FM_WORKPATH then
				SetPathMode(work_path, FM_WORKPATH)
			end if
			set all_hashes_pass to HashesMatch(all_hashes_pass, work_path, plist_file, KEY_WORKPATH_HASH)
		else
			set work_path to missing value
		end if
	end if
	if work_path is missing value then
		set all_hashes_pass to false
		set tmp to system attribute "TMPDIR"
		if tmp is NON then
			set tmp to "/tmp/"
		else if not (tmp ends with "/") then
			set tmp to tmp & "/"
		end if
		set work_path to tmp & GetNewUUID()
		CreateDirectory(work_path, FM_WORKPATH)
		SetPListValue(plist_file, KEY_WORKPATH_VAL, string, work_path)
		SetPListValue(plist_file, KEY_WORKPATH_HASH, string, GetStringHash(work_path))
	end if
	--
	-- mesg_path and exec_path are not set in the plist, as they're always relative to work_path
	-- however, their hashes are stored, in case they get renamed
	--
	set mesg_path to work_path & MESG_DIR_NAME
	set exec_path to work_path & EXEC_FILE_NAME
	set all_hashes_pass to HashesMatch(all_hashes_pass, mesg_path, plist_file, KEY_MESGPATH_HASH)
	set all_hashes_pass to HashesMatch(all_hashes_pass, exec_path, plist_file, KEY_EXECPATH_HASH)
	--
	-- message directory next
	--
	set tgt_exist to false
	set tgt_info to GetPathInfo(mesg_path)
	if tgt_info is not missing value then
		if kind of tgt_info is FT_DIRECTORY then
			if perms of tgt_info is not FM_MESGPATH then
				SetPathMode(mesg_path, FM_MESGPATH)
			end if
			set tgt_exist to true
		else
			-- whatever's there, blow it away
			do shell script "/bin/rm -f " & quoted form of mesg_path
		end if
	end if
	if not tgt_exist then
		CreateDirectory(mesg_path, FM_MESGPATH)
	end if
	--
	-- almost anything will invalidate the upload script
	--
	set tgt_info to GetPathInfo(exec_path)
	if tgt_info is missing value then
		set all_hashes_pass to false
	else if kind of tgt_info is not FT_REGULAR then
		-- whatever it is, blow it away
		do shell script "/bin/rm -rf " & quoted form of exec_path
		set all_hashes_pass to false
	end if
	if all_hashes_pass then
		set tgt_hash to GetPListValue(plist_file, KEY_EXECFILE_HASH)
		if tgt_hash is missing value or tgt_hash is not GetContentHash(exec_path) then
			set all_hashes_pass to false
		else if perms of tgt_info is not FM_EXECFILE then
			SetPathMode(exec_path, FM_EXECFILE)
		end if
	end if
	if not all_hashes_pass then
		WriteUploadScript(work_path, mesg_path, exec_path, knujon_id)
		SetPListValue(plist_file, KEY_EXECFILE_HASH, string, GetContentHash(exec_path))
	end if
	
	return {mesgext:MESG_FILE_EXT, mesgpath:mesg_path, stagemb:stage_mb, ulscript:exec_path}
end GetAppProperties

on ValidateLocalMailbox(mb_name)
	tell application "Mail"
		if not running then
			launch
		end if
		try
			set n to (name of mailbox mb_name) as rich text
			return {ok:true, data:n}
		end try
		set tmp to my TrimString(mb_name)
		if tmp is not mb_name then
			try
				set n to (name of mailbox tmp) as rich text
				return {ok:true, data:n}
			end try
		end if
		try
			set n to (name of (make new mailbox with properties {name:tmp})) as rich text
			return {ok:true, data:n}
		on error
			return {ok:false, data:"Invalid Mailbox Name '" & tmp & "'."}
		end try
	end tell
end ValidateLocalMailbox

--
-- User Interaction
--

--
-- Buttons
--
property B_D : "Use Default"
property B_K : "OK"
property B_N : "No"
property B_R : "Retry"
property B_X : "Cancel"
property B_Y : "Yes"
--
-- Loop States
--
property L_CONF_DEF : 1
property L_CONF_ENT : 2
property L_CONG_SPC : 3
property L_EMPTY : 4
property L_INIT : 5
property L_INVAL : 6
property L_MISMATCH : 7

property STAGING_MB_DESC : "This application uses a local staging mailbox within Apple Mail.
It's MUCH more reliable, and faster, to copy messages from remote servers' junk mail folders to a local folder as an intermediate step.
During processing, messages are moved to this mailbox and, once handled, deleted.
You can use whatever you like, just as long as you create it under 'On My Mac', or you can use the default.
Either way, if it doesn't exist, it will be created. You are STRONGLY advised against using a mailbox you use for anything else!
Note that messages in the staging directory are assumed to have already been reviewed and are not tested for 'read' or 'junk' status.
"

on DisplayResult(msg_count)
	if msg_count = 0 then
		set msg to "No eligible spam messages were found."
	else if msg_count = 1 then
		set msg to "1 message was uploaded to KnujOn."
	else
		set msg to (msg_count as text) & " messages were uploaded to KnujOn."
	end if
	display dialog msg buttons B_K default button B_K with title "Upload Spam" with icon note
end DisplayResult

on GetStagingMB()
	set TTL to "Staging Mailbox Initialization"
	
	set M_PROMPT to "Enter the staging mailbox name to use, or click \"" & B_D & "\" to use the default \"" & DEF_STAGEMB_NAME & "\"."
	set M_INIT to STAGING_MB_DESC & linefeed & M_PROMPT
	set M_EMPTY to "Staging mailbox name cannot be empty." & linefeed & M_PROMPT
	
	set msg to M_INIT
	set ico to note
	repeat
		set rr to display dialog msg default answer NON buttons {B_X, B_D, B_K} Â
			default button B_K cancel button B_X with title TTL with icon ico
		if (button returned of rr) is B_K then
			set ent to (text returned of rr)
			if ent is NON then
				set msg to M_EMPTY
				set ico to caution
			else
				set check to ValidateLocalMailbox(ent)
				if ok of check then
					return data of check
				else
					set msg to (data of check) & linefeed & M_PROMPT
					set ico to caution
				end if
			end if
		else
			return DEF_STAGEMB_NAME
		end if
	end repeat
end GetStagingMB

on GetUserId()
	set TTL to "KnujOn Initialization"
	
	set M_INIT_UID to "Enter your KnujOn ID or click \"" & B_D & "\" for the generic \"" & DEF_KNUJONID & "\" ID."
	set M_CONF_UID to "Confirm your KnujOn ID."
	set M_MISMATCH to "Entries didn't match, try again." & linefeed & M_INIT_UID
	set M_CONF_DEF to "You've chosen to use the default KnujOn ID. You won't be able to track submissions using this ID. Are you sure?"
	set M_CONF_SPC to "You've entered a KnujOn ID containing whitespace. When this script was written, whitespace was not allowed. Do you really want to use this ID?"
	set M_INIT_NON to "KnujOn ID cannot be empty." & linefeed & M_INIT_UID
	
	set mode to L_INIT
	set ent1 to NON
	repeat
		if (mode = L_INIT) then
			set rr to display dialog M_INIT_UID default answer NON buttons {B_X, B_D, B_K} Â
				default button B_K cancel button B_X with title TTL with icon note
			if (button returned of rr) is B_K then
				set ent1 to (text returned of rr)
				if ent1 is NON then
					set mode to L_EMPTY
				else
					set mode to L_CONF_ENT
				end if
			else
				set mode to L_CONF_DEF
			end if
		else if (mode = L_CONF_ENT) then
			set rr to display dialog M_CONF_UID default answer NON buttons {B_X, B_R, B_K} Â
				default button B_K cancel button B_X with title TTL with icon note
			if (button returned of rr) is B_K then
				set ent2 to (text returned of rr)
				if ent2 is ent1 then
					if ent2 contains space or ent2 contains tab then
						set mode to L_CONG_SPC
					else
						return ent2
					end if
				else
					set mode to L_MISMATCH
				end if
			else
				set mode to L_INIT
			end if
		else if (mode = L_CONF_DEF) then
			set rr to display dialog M_CONF_DEF buttons {B_X, B_N, B_Y} Â
				default button B_N cancel button B_X Â
				with title TTL with icon caution
			if (button returned of rr) is B_Y then
				return DEF_KNUJONID
			else
				set mode to L_INIT
			end if
		else if (mode = L_CONG_SPC) then
			set rr to display dialog M_CONF_SPC buttons {B_X, B_N, B_Y} Â
				default button B_Y cancel button B_X Â
				with title TTL with icon stop
			if (button returned of rr) is B_Y then
				return ent1
			else
				set mode to L_INIT
			end if
		else if (mode = L_EMPTY) then
			set rr to display dialog M_INIT_NON default answer NON buttons {B_X, B_D, B_K} Â
				default button B_K cancel button B_X with title TTL with icon caution
			if (button returned of rr) is B_K then
				set ent1 to (text returned of rr)
				if ent1 is NON then
					set mode to L_EMPTY
				else
					set mode to L_CONF_ENT
				end if
			else
				set mode to L_CONF_DEF
			end if
		else if (mode = L_MISMATCH) then
			set rr to display dialog M_MISMATCH default answer NON buttons {B_X, B_D, B_K} Â
				default button B_K cancel button B_X with title TTL with icon caution
			if (button returned of rr) is B_K then
				set ent1 to (text returned of rr)
				if ent1 is NON then
					set mode to L_EMPTY
				else
					set mode to L_CONF_ENT
				end if
			else
				set mode to L_CONF_DEF
			end if
		else
			error "Unhandled mode " & quote & mode & quote number 56
		end if
	end repeat
end GetUserId

on HashesMatch(MatchResult, InString, PListFile, PListKey)
	set tmp to GetPListValue(PListFile, PListKey)
	set val to GetStringHash(InString)
	if tmp is val then
		return MatchResult
	end if
	SetPListValue(PListFile, PListKey, string, val)
	return false
end HashesMatch

on WriteUploadScript(work_path, mesg_path, exec_path, knujon_id)
	--
	-- The script will be run in the system shell (/bin/sh), so there's
	-- no need to specify it.
	--
	-- Make sure we exit on any error, so that
	-- a subsequent run will pick up where it failed
	--
	set scr to "# executing in /bin/sh, no need to set it
# exit on error, so we can pick up where we left off
set -e

# set externally
addr='http://www.knujon.com/uploadjunk.php'
ulid='" & knujon_id & "'
wdir='" & work_path & "'
mdir='" & mesg_path & "'

# internal
arch=\"$ulid.zip\"
list=\"$ulid.list\"
lock=\"$ulid.lock\"
curl='/usr/bin/curl --silent --output /dev/null --stderr /dev/null'

# do everything from the working directory
cd \"$wdir\"

# one at a time
# lock timeout is required because of the shell's -e option!
/usr/bin/lockfile -l 666 -s 33 \"$lock\"

# create the archive
/usr/bin/zip -rDjX \"$arch\" \"$mdir\" -i '*" & MESG_FILE_EXT & "' >\"$list\"

# on success, get the file count
nmsg=\"$(/usr/bin/wc -l <\"$list\")\"

# upload the archive
$curl --form \"uploadedfile=@$arch\" --form \"idname=$ulid\" \"$addr\"

# on success, clean up what's been sent
/bin/rm -f \"$arch\" \"$list\"
/bin/rm -rf \"$mdir\"
/bin/mkdir -m " & FM_MESGPATH & " \"$mdir\"

# release the lock!
/bin/rm -f \"$lock\"

#finally, report how many messages were sent
echo $nmsg
"
	--
	-- write the script, creating or truncating as needed
	--
	set fd to (open for access exec_path with write permission)
	set eof fd to 0
	write (scr as text) to fd
	close access fd
	SetPathMode(exec_path, FM_EXECFILE)
end WriteUploadScript

--
-- PList I/O
--

on GetPListValue(PListPath, PListKey)
	set v to missing value
	tell application "System Events"
		try
			tell contents of (property list file PListPath)
				set v to value of property list item PListKey
			end tell
		end try
	end tell
	return v
end GetPListValue

on GetPListRecord(PListPath, PListKey)
	set n to missing value
	set k to missing value
	set v to missing value
	tell application "System Events"
		try
			tell property list item PListKey of contents of (property list file PListPath)
				set n to name
				set k to kind
				set v to value
			end tell
		on error
			return missing value
		end try
	end tell
	return {name:n, kind:k, value:v}
end GetPListRecord

on SetPListRecord(PListPath, PListRecord)
	SetPListValue(PListPath, name of PListRecord, kind of PListRecord, value of PListRecord)
end SetPListRecord

on SetPListValue(PListPath, PListKey, PListType, PListValue)
	set n to PListKey as string
	set t to PListType
	set v to PListValue
	
	tell application "System Events"
		if (class of t) is not class then
			set t to (t as string)
			if t is "boolean" or t is "bool" then
				set t to boolean
			else if t is "date" then
				set t to date
			else if t is "float" or t is "real" then
				set t to real
			else if t is "integer" or t is "int" then
				set t to integer
			else if t is "list" then
				set t to list
			else if t is "float" or t is "number" or t is "real" then
				set t to number
			else if t is "record" then
				set t to record
			else if t is "string" or t is "text" then
				set t to string
			else
				set t to data
			end if
		end if
		if (class of v) is not t then
			if t is boolean then
				set v to (v as boolean)
			else if t is date then
				set v to (v as date)
			else if t is integer then
				set t to number
				set v to (v as integer)
			else if t is list then
				set v to (v as list)
			else if t is number then
				if class of v is not integer then
					set v to (v as number)
				end if
			else if t is real then
				set t to number
				set v to (v as real)
			else if t is record then
				set v to (v as record)
			else if t is string then
				set v to (v as string)
			else
				set t to data
			end if
		end if
		try
			set plist to property list file PListPath
		on error
			set plist to make new property list file with properties {name:PListPath}
		end try
		tell contents of plist
			try
				tell property list item PListKey
					if kind is t then
						set value to v
					else
						error
					end if
				end tell
			on error
				make new property list item at end with properties {name:n, kind:t, value:v}
			end try
		end tell
	end tell
end SetPListValue

--
-- General Utility Operations
--

on CreateDirectory(fs_path, fs_mode)
	do shell script ("/bin/mkdir -m " & quoted form of fs_mode & space & quoted form of fs_path)
end CreateDirectory

on GetContentHash(file_path)
	last word of (do shell script ("/usr/bin/openssl sha1 " & quoted form of file_path))
end GetContentHash

on GetNewUUID()
	do shell script "/usr/bin/uuidgen"
end GetNewUUID

on GetPathBasename(fs_path)
	set tid to AppleScript's text item delimiters
	set AppleScript's text item delimiters to "/"
	set tmp to last item of (text items of fs_path)
	set AppleScript's text item delimiters to tid
	return tmp
end GetPathBasename

on GetPathDirname(fs_path)
	set tid to AppleScript's text item delimiters
	set AppleScript's text item delimiters to "/"
	set tmp to text items of fs_path
	set tmp to (items 1 through ((count tmp) - 1) of tmp) as text
	set AppleScript's text item delimiters to tid
	return tmp
end GetPathDirname

on GetPathInfo(fs_path)
	try
		set tmp to do shell script "/usr/bin/stat -nf '%Lp:%HT' " & quoted form of fs_path
		set tid to AppleScript's text item delimiters
		set AppleScript's text item delimiters to ":"
		set tmp to text items of tmp
		set AppleScript's text item delimiters to tid
		return {kind:((item 2 of tmp) as text), perms:((item 1 of tmp) as text)}
	on error
		return missing value
	end try
end GetPathInfo

on GetStringHash(in_string)
	do shell script ("/usr/bin/printf " & quoted form of in_string & " | /usr/bin/openssl sha1")
end GetStringHash

on SetPathMode(fs_path, fs_mode)
	do shell script ("/bin/chmod " & quoted form of fs_mode & space & quoted form of fs_path)
end SetPathMode

on TrimString(in_string)
	set wsc to space & tab & linefeed & return
	set len to count in_string
	set fst to 1
	set lst to len
	repeat while fst ² lst and wsc contains (character fst of in_string)
		set fst to (fst + 1)
	end repeat
	repeat while fst ² lst and wsc contains (character lst of in_string)
		set lst to (lst - 1)
	end repeat
	if fst = 1 and lst = len then
		return in_string
	end if
	if fst > lst then
		return NON
	end if
	return (characters fst through lst of in_string) as text
end TrimString

