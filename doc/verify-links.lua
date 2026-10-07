--- Check if path can be read.
-- (Replace with pandoc.exists once Pandoc 3.7.1 or higher is
-- targeted.)
local function isreadable(path)
   local fh = io.open(path, "r")
   if fh == nil then
      return false
   end
   io.close(fh)
   return true
end

--- Verify local link targets.
-- Relies on Pandoc being called with one input file at a time.
function Link (el)
   if el.target:sub(1, 8) == "https://" then
      -- Not a local target, not checked.
      return nil
   end
   if el.target:sub(1, 7) == "http://" then
      -- Not a local target, not checked.
      return nil
   end
   local docpath = PANDOC_STATE.input_files[1]
   if el.target:len() == 0 then
      io.stderr:write(
         string.format(
            "Warning: While rendering %s: empty link target for %s.\n",
            docpath,
            el.content))
   end
   local target
   anchoridx = el.target:find("#", 1, true)
   if anchoridx then
      target = el.target:sub(1, anchoridx - 1)
   else
      target = el.target
   end
   if target:len() == 0 then
      return nil
   end
   local path = pandoc.path.join({
         pandoc.path.directory(docpath),
         target})
   if not isreadable(path) then
      io.stderr:write(
         string.format(
            "Warning: While rendering %s: link target %s not readable.\n",
            docpath,
            path))
   end
   return nil
end
