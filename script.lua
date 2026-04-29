while true do
	-- create part
	local part = Instance.new("Part")

	-- random size (small to big)
	local size = math.random(2, 10)
	part.Size = Vector3.new(size, size, size)

	-- random position in the air
	part.Position = Vector3.new(math.random(-50, 50), math.random(50, 100), math.random(-50, 50))

	part.Anchored = false
	part.Material = Enum.Material.SmoothPlastic
	part.Color = Color3.fromRGB(math.random(0, 255), math.random(0, 255), math.random(0, 255))

	part.Parent = workspace

	-- optional: auto delete after some time (prevents lag)
	game:GetService("Debris"):AddItem(part, 10)

	wait(0.3) -- spawn rate
end
