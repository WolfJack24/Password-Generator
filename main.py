from customtkinter import ThemeManager, set_default_color_theme

from gui import App

def main() -> None:
    ThemeManager.load_theme("./Assets/Theme/blue_in_hex.json")
    set_default_color_theme("./Assets/Theme/blue_in_hex.json")

    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()