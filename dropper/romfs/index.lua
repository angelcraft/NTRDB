Roboto = Font.load("romfs:/Roboto.ttf")
TopScr = Screen.loadImage("romfs:/TopScr.png")
BotScr = Screen.loadImage("romfs:/BotScr.png")
BotScr_Install = Screen.loadImage("romfs:/BotScr_Install.png")
f = io.open('romfs:/PlugInfo_STYPE.txt', FREAD)
SysType = io.read(f,0,4)
io.close(f)
f = io.open('romfs:/PlugInfo_DOWN.txt', FREAD)
DLink = io.read(f, 0, io.size(f))
io.close(f)
f = io.open('romfs:/PlugInfo_TID.txt', FREAD)
TID = io.read(f, 0, io.size(f))
io.close(f)
f = io.open('romfs:/PlugInfo_NAME.txt', FREAD)
NAME = io.read(f, 0, io.size(f))
io.close(f)
System.currentDirectory("/")
System.createDirectory("/plugin")
System.createDirectory("/plugin/"..TID)
System.currentDirectory("/plugin/"..TID.."/")
Font.setPixelSizes(Roboto,16)
function install()
	Screen.waitVblankStart()
	Screen.refresh()
	Screen.drawImage(0,0,TopScr,TOP_SCREEN)
	Screen.drawImage(0,0,BotScr_Install,BOTTOM_SCREEN)
	Font.setPixelSizes(Roboto,24)
	local text = "Install plugin? Click at touch screen"
	local x = 200 - (string.len(text) - 2) / 2 * 8
	local y = 120 - 8
	Font.print(Roboto, x, y, text, Color.new(255,255,255), TOP_SCREEN)
	Screen.flip()
	while true do
		pad = Controls.read()
		if (Controls.check(pad,KEY_TOUCH)) then
			x,y = Controls.readTouch()
			if x > 101 and x < 220 and y > 97 and y < 143 then
				print("Downloading...")
				Network.downloadFile(DLink, "/plugins/"..TID.."/"..NAME..".plg")
				System.addNews("Plugin "..NAME.. "were installed!", "Have fun!\n\noctonezd.pw", "romfs:/NewsApplet.png", true)
				System.exit()
			elseif x > 64 and x < 257 and y > 209 and y < 239 then
				System.exit()
			end
		end
	end
end
function print( text )
	Screen.waitVblankStart()
	Screen.refresh()
	Screen.drawImage(0,0,TopScr,TOP_SCREEN)
	Screen.drawImage(0,0,BotScr,BOTTOM_SCREEN)
	Font.setPixelSizes(Roboto,24)
	local x = 200 - (string.len(text) - 2) / 2 * 8
	local y = 120 - 8
	Font.print(Roboto, x, y, text, Color.new(255,255,255), TOP_SCREEN)
	Screen.flip()
end
t = System.listCIA()
for k,v in pairs(t) do
	if v["product_id"] == "CTR-P-NTRDRP" then
		System.uninstallCIA(v["access_id"], SDMC)
		break
	end
end
print("Reading system model...")
local model = System.getModel()
print("Please wait...")
if SysType == "n3ds" then
	if model == 2 or model == 4 then
		install()
	else
		print("You have wrong console model! New3DS Only!")
		while true do
			pad = Controls.read()
			if (Controls.check(pad,KEY_HOME)) then
				System.exit()
			end
		end
	end
elseif SysType == "o3ds" then
	if model == 0 or model == 1 or model == 3 then
		install()
	else
		print("You have wrong console model! Old3DS ONLY!")
		while true do
			pad = Controls.read()
			if (Controls.check(pad,KEY_HOME)) then
				System.exit()
			end
		end
	end
elseif SysType == "0any" then
	install()
end