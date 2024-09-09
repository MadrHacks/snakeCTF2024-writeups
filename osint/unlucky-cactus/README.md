# unlucky-cactus [_snakeCTF 2024 Quals_]

**Category**: OSINT

## Description

From KLGA to KSEA, via KCLT, encountering some unpleasant birds.

"Huston, we have a problem!"

What is the name of the superhero?

## Solution

### Understanding the context

First, the context must be understood: KLGA, KSEA, and KCLT are ICAO codes for three airports. From this, it can be inferred that the scenario involves an aeroplane flight.

### Other useful hints

The challenge name includes "unlucky," and the description references the famous phrase, "Houston, we have a problem." These clues strongly suggest that something has gone wrong, most likely involving a plane crash.

### Google Search

A simple Google search using the three ICAO codes along with the word "crash" quickly leads to an article titled "13 Years Later - US 1549," which details the plane crash.

### Analysis of the information found

Upon reading the article, several details confirm that the correct path is being followed:

- "US 1549, also referred to as Cactus 1549"
- "[...] US 1549 struck the frigid waters of the Hudson River"

The first detail connects to the challenge name, as "unlucky-cactus" clearly references Cactus 1549. The second detail relates to the challenge description, where the phrase "Houston, we have a problem" mirrors the name of the splashdown location, the Hudson River.

### Extracting the flag

The challenge asks for the name of the pilot involved in a famous plane crash. A search for "Cactus 1549 flight" immediately leads to a Wikipedia page that provides the full name, including the nickname and surname, of the pilot.
