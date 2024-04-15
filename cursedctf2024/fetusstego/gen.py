from PIL import Image
from PIL import ImageDraw
from PIL import ImageFont
import random
 
flag = "cursed{interlace_pixels_stego_huh??}"
print(len(flag))

def gen_random_color():
    r = random.randint(0, 255)
    g = random.randint(0, 255)
    b = random.randint(0, 255)
    return (r, g, b)

imgs = []
W, H = 24, 24
for i, c in enumerate(flag):
    # Open an Image
    img =  Image.new(mode="RGB", size=(W, H))
     
    # Call draw Method to add 2D graphics in an image
    I1 = ImageDraw.Draw(img)
     
    # Custom font style and font size
    myFont = ImageFont.truetype('comic.ttf', 12)

    message = c
    w, h = I1.textsize(message, font=myFont)
    I1.text(((W-w)/2, (H-h)/2), message, font=myFont, fill=gen_random_color())
     
     
    # Display edited image
    imgs.append(img)
    img.save(f"flag_{i}.png")
#    img.show("abic")

print(imgs)
flag_img = Image.new(mode="RGB", size=(W*6, H*6))
for x in range(W):
    for y in range(H):
        for i in range(6):
            for j in range(6):
                flag_img.putpixel((x*6+i, y*6+j), imgs[i*6+j].getpixel((x, y)))

flag_img.show("abi")
flag_img.save("flag.png")


