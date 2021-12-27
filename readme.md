# Introduction

If we use Burp Community version. Then we don't have the ability to persist our project. One thing I want to persist is items in Sitemap. Burp Suite provides an option to export sitemap items at `Target` > `Site map` > `right-click on an item below` > `Save selected items`. But it doesn't have option to import back in.

This Burp extension solves this problem

# Installation

1. Download/Clone this source to your computer.
2. In your Burp, go to `Extender` tab > `Options` > `Python Environment` and locate `jython-standalone-2.7.2.jar` location
3. In your Burp, go to `Extender` tab > `Extensions` > `Burp Extensions` > `Add` > Choose Python in `Extension type` and locate `main.py` location

Note: After step 3, you see a message `no sitemap xml file found in {path}`. That's because this extension run on load. So when we want to run this extension, just reload it.

# How to use

- Put sitemap file that you want to import into `source_sitemap` folder. It has to end with ".xml"
- To trigger import action, Go to `Extender` > `Extensions` > uncheck and recheck `Sitemap Importer` again

# example usage

- Export sitemap file
![screenshot 1](screenshots/screenshot_1.png?raw=true)

- Put this file into `sitemap_source` folder
![screenshot 2](screenshots/screenshot_2.png?raw=true)

- Reload `Sitemap Importer` to trigger import action
![screenshot 3](screenshots/screenshot_3.png?raw=true)
