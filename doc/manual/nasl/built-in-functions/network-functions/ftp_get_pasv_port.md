# ftp_get_pasv_port

## NAME

**ftp_get_pasv_port** - sends the “PASV” command on the open socket, parses the returned data and returns the chosen “passive” port

## SYNOPSIS

*any* **ftp_get_pasv_port**(socket:*socket*);

**ftp_get_pasv_port** It takes one named argument: socket.

## DESCRIPTION

This function sends the “PASV” command on the open socket, parses the returned data and returns the chosen “passive” port.

## RETURN VALUE

Return the passive port or Null
