--- Decrement header levels (and discard level 1 headers).
function Header (el)
   if el.level == 1 then
      return {}
   end
   el.level = el.level - 1
   return el
end
