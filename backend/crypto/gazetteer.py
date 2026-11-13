"""
Bundled, offline gazetteer for the blind tokenizer (no network, no model, no external files).

All entries are lower-case and NFC-normalised; lookups are O(1) set/dict hits per token, never one
large alternation regex. The lists are deliberately conservative where a name or place is also an
ordinary English or Dutch word: those live in the AMBIGUOUS_* sets and are only treated as PII when
the surrounding context supplies extra evidence (see `blind_tokenizer._gazetteer_spans`).
"""

from typing import Dict, FrozenSet, List, Tuple


def _words(block: str) -> FrozenSet[str]:
    return frozenset(w.strip().lower() for w in block.split() if w.strip())


# ---------------------------------------------------------------------------------------------
# First names (Dutch + international). Short forms that are ordinary words in EN/NL ("an", "al",
# "ad", "ed", "can", "said", "do", "bo") are intentionally absent.
# ---------------------------------------------------------------------------------------------
_FIRST_NAMES_NL = """
    sem guus jan piet kees klaas henk gerrit dirk joost jeroen wouter willem wim bart bram daan
    luuk thijs stijn sven finn levi gijs teun tijn siem jip pepijn mees hugo jens tygo olivier
    boaz joep ties tuur koen ruud roel rik rick niels michiel martijn maarten marco marcel remco
    ronald rutger sander stefan sjoerd sietse tjeerd wiebe hessel jelle jelmer douwe folkert
    freek frits geert gert gerard hein huub huib harm hendrik johan johannes jos joris jurgen
    jurriaan kevin lars laurens leon leendert lucas luc matthijs maurits menno mitchell nick
    nico onno otto pieter quinten reinier ruben rens robin roy sjaak thom tim tom ton toon
    twan valentijn vincent wessel wilco wilbert yorick youri jasper jochem job jesse jorrit
    emma julia mila tess sophie zoë zoe sara nora yara eva liv lotte evi noor anna saar lieke
    fleur isa lisa sanne femke anouk esther ingrid marieke petra monique linda sandra karin
    wendy ellen marloes manon sofie roos elin fenna ilse ivy jasmijn lina maud nina olivia romy
    sarah lynn noa nova hailey amira esmee floor hannah jill kiki lara liz lois loïs lizzy marit
    merel naomi rosa sofia vera yfke zara mirthe suze puck nienke iris joke truus riet mien
    corrie annie greet ans tineke trees wilma anneke astrid bianca carla chantal daphne debby
    elise elsbeth erica hilde irene janneke jolanda judith kim laura lies lisette marjolein
    mirjam nathalie nicole patricia renate rianne sabine saskia simone tamara vanessa willemijn
    yvonne annemiek annelies anja inge els gerda hanneke henny jannie joyce lieve marjan
    mariska miranda mieke nel nelleke rietje sanneke trijntje wilhelmina ben dan wil les lot
    bas mats storm jet floris benthe fiene fenne isis jente juul lotus luna maartje meike
    milou myrthe nikki pien quinty silke tamar tirza veerle wies ymke dewi demi
"""

_FIRST_NAMES_EN = """
    james john robert michael william david richard joseph thomas charles christopher daniel
    matthew anthony donald steven paul andrew joshua kenneth kevin brian george edward timothy
    jason jeffrey ryan jacob gary nicholas eric jonathan stephen larry justin scott brandon
    benjamin samuel gregory alexander patrick raymond jack dennis jerry tyler aaron adam henry
    nathan douglas zachary peter kyle walter ethan jeremy harold keith christian roger noah
    gerald carl terry sean austin arthur lawrence dylan bryan joe jordan billy bruce albert
    willie gabriel logan alan wayne roy ralph randy eugene vincent russell elijah louis bobby
    philip johnny oliver harry charlie oscar leo archie freddie theo alfie isaac toby liam
    mason owen caleb connor ian colin craig darren gavin graham neil nigel simon stuart trevor
    martin marcus jake luke sam max will mark bill rob ray pat sue frank dean drew miles lance
    victor howard herbert stanley leonard frederick clarence ernest francis glenn jimmy
    marvin travis troy curtis shane derek jared cody chad brett clinton dustin todd hunter
    mary jennifer elizabeth barbara susan jessica karen nancy betty margaret ashley kimberly
    emily donna michelle carol amanda dorothy melissa deborah stephanie rebecca sharon cynthia
    kathleen amy angela shirley brenda pamela helen samantha katherine christine debra rachel
    carolyn janet catherine maria heather diane ruth julie joan evelyn megan andrea cheryl
    jacqueline martha gloria teresa ann frances kathryn janice jean abigail alice judy denise
    amber doris marilyn danielle beverly isabella theresa diana natalie brittany charlotte
    marie kayla alexis lori chloe ella lucy mia amelia isla ava poppy grace rose hope faith joy
    april may june victoria virginia madison kelly lauren christina sophia ruby lily daisy
    holly heather hazel violet jade pearl dawn eve penny ginger sandy summer autumn harper
    avery scarlett aria layla zoey nevaeh riley eleanor hazel stella paisley audrey skylar
    claire lucille madeline caroline kennedy kinsley allison gabriella alyssa naomi elena
    sadie hailey bella aaliyah josephine leah ellie
"""

_FIRST_NAMES_INTL = """
    jose josé juan carlos luis miguel javier pedro pablo diego alejandro fernando jorge manuel
    antonio francisco rafael sergio raul raúl ana lucía lucia sofía isabel marta paula pilar
    beatriz joão joao rodrigo mateo santiago alberto enrique ignacio
    marco luca giuseppe giovanni francesco alessandro matteo lorenzo paolo roberto stefano
    giulia chiara francesca valentina alessia martina federica riccardo davide simone
    klaus jürgen jurgen wolfgang andreas markus matthias sebastian tobias florian lukas jonas
    felix maximilian karl heinz helmut uwe dieter günter gunter monika ursula gabriele claudia
    susanne katrin lena lea leonie johanna friedrich
    pierre jacques michel philippe alain nicolas françois francois antoine julien mathieu
    laurent christophe sébastien sebastien guillaume thierry camille chloé julie isabelle
    céline celine aurélie aurelie émilie emilie léa lea inès ines renée renee rené rene
    élodie elodie amélie amelie benoît benoit
    piotr krzysztof tomasz paweł pawel michał michal marcin kasia katarzyna agnieszka
    magdalena joanna ewa ivan dmitri dmitry sergei sergey alexei alexey vladimir andrei
    nikolai olga natasha svetlana tatiana irina anastasia ekaterina elena
    anders ingrid astrid freya sigrid björn bjorn magnus henrik
    mohammed mohamed muhammad mohammad ahmed ahmad omar youssef yusuf ibrahim hassan hussein
    mustafa mehmet emre fatima fatma aisha ayşe ayse zeynep elif murat burak deniz emir kerem
    yasin hamza bilal khalid karim rachid samir nadia leila layla yasmin salma amina meryem
    hatice hakan selin ali
    raj rahul priya amit anil sunil vijay deepak arjun ravi sanjay neha pooja anjali sita
    krishna ananya aditya rohan vikram kiran sachin
    wei ming hiroshi yuki kenji takashi haruka sakura minh linh
    kwame kofi amara chidi ngozi oluwaseun tunde
    marcus sophia
"""

# Names that are also everyday EN/NL words (or months, products, places). Treated as a name only
# with extra evidence: a person preposition/role word before it, and (in lower case) a surname.
_AMBIGUOUS_FIRST_NAMES = """
    will mark rose april may june august grace faith hope bill max art joy dawn summer autumn
    winter sky ray pat sue rob jack frank chase drew gene guy lance miles nick penny ruby
    amber iris lily daisy ivy holly hazel violet jade pearl eve ginger sandy dean don jean
    kay ben dan wil les lot bas mats storm jet floor roos fleur lieve puck joke trees riet
    greet lies toon ton mees job merel harm christian roger randy oscar leo jordan victoria
    virginia madison charlotte brittany poppy carol nova ada julia joyce hunter mason harper
    autumn stella sander heather sterling luna isis lotus kelly bob chad aria paisley robin rosa ties
    anders
"""

FIRST_NAMES: FrozenSet[str] = _words(_FIRST_NAMES_NL) | _words(_FIRST_NAMES_EN) | _words(_FIRST_NAMES_INTL)
AMBIGUOUS_FIRST_NAMES: FrozenSet[str] = _words(_AMBIGUOUS_FIRST_NAMES)
FIRST_NAMES = FIRST_NAMES | AMBIGUOUS_FIRST_NAMES

# Months and weekdays (EN + NL): never a single-word name, never a surname.
CALENDAR_WORDS: FrozenSet[str] = _words(
    """
    january february march april may june july august september october november december
    januari februari maart mei juni juli augustus oktober
    jan feb mar apr jun jul aug sep sept oct okt nov dec
    monday tuesday wednesday thursday friday saturday sunday
    maandag dinsdag woensdag donderdag vrijdag zaterdag zondag
    """
)

# ---------------------------------------------------------------------------------------------
# Words that end a candidate name: a first name followed by one of these is not a full name
# ("mark the invoice", "will pay later", "jan is ziek"). Compact EN + NL function words and
# frequent verbs/nouns of business prompts.
# ---------------------------------------------------------------------------------------------
NAME_STOP: FrozenSet[str] = _words(
    """
    the a an and or but nor if then than so to of in on at by for from with without about as
    into onto over under after before since until via per re cc vs versus against between
    through during within around near off out up down
    is are was were be been being am has have had do does did will would shall should can
    could may might must not no yes isn't wasn't don't doesn't won't can't
    this that these those it its he she they we you i me him her them us my your his our their
    who whom whose which what when where why how all any some each every both either neither
    other another such same own more most less least much many few several
    please thanks thank today tomorrow yesterday tonight now later soon again also too very
    just only even still already here there asap ok okay hi hello dear regards cheers
    said says say asked asks ask told tells tell wants wanted want needs needed need gets got
    get sent sends send pays paid pay owes owed approved approves approve signed signs sign
    called calls call emailed mailed mails mail wrote writes write knows know thinks think
    works work worked joined join left leaves leave agreed agree confirmed confirms confirm
    requested requests request received receives receive gave gives give made makes make
    took takes take reports reported report reviewed reviews review checked checks check
    updated updates update created creates create deleted deletes delete booked books book
    moved moves move started starts start finished finishes finish done doing going
    invoice invoices payment payments money cash euro euros dollar dollars account accounts
    team teams office department project projects meeting meetings budget budgets file files
    document documents contract contracts order orders bonus salary data notes note
    de het een en of maar als dan dat die dit deze is zijn was waren wordt worden werd heeft
    hebben had kan kunnen zal zullen moet moeten mag mogen wil wilt willen gaat gaan ging doet
    doen deed niet geen wel ook nog al er hier daar naar aan voor van met door op in uit bij
    om over onder tot te toe zonder tegen na nu vandaag morgen gisteren straks later graag
    alsjeblieft alstublieft bedankt dank groeten hij zij ze wij we jij je u ik hem haar hun
    ons onze mijn jouw uw wie wat waar wanneer waarom hoe alle elke iedere betaalt betaald
    betalen stuurt stuur gestuurd sturen zegt zei vraagt vroeg belt bel mailt factuur
    facturen rapport betaling geld team kantoor afdeling project vergadering inzake betreft
    krijgt kreeg komt kwam heb hebt ben bent bijvoorbeeld zo maar want omdat terwijl
    """
) | CALENDAR_WORDS

# Words that make the NEXT word a person reference (prepositions of person, role/title words,
# greeting and contact verbs). Used as extra evidence for AMBIGUOUS_FIRST_NAMES.
PERSON_PREPOSITIONS: FrozenSet[str] = _words("to for from by aan voor van door met naar with cc attn")
ROLE_WORDS: FrozenSet[str] = _words(
    """
    employee patient patiënt client klant vendor customer lead recipient user medewerker
    werknemer leverancier subject mr mrs ms dr dhr mevr
    """
)
CONTACT_WORDS: FrozenSet[str] = _words(
    "dear beste hi hoi hallo hello mail email e-mail call bel contact ask tell vraag ping"
)
PERSON_CUES: FrozenSet[str] = PERSON_PREPOSITIONS | ROLE_WORDS | CONTACT_WORDS

# Dutch/European surname particles (lower case). Multi-word particles are matched pairwise.
NAME_PARTICLES: FrozenSet[str] = _words("van de den der ter ten von zu du la le da di del dos das")
NAME_PARTICLE_PAIRS: FrozenSet[Tuple[str, str]] = frozenset(
    {("van", "der"), ("van", "den"), ("van", "de"), ("de", "la"), ("von", "der"), ("de", "los")}
)

# ---------------------------------------------------------------------------------------------
# Places: Dutch municipalities/towns of some size, Belgian cities and large world cities.
# Multi-word names are written with spaces; hyphenated names stay one token.
# ---------------------------------------------------------------------------------------------
_PLACES_NL = """
    amsterdam rotterdam den_haag the_hague hague 's-gravenhage s-gravenhage utrecht eindhoven
    groningen tilburg almere breda nijmegen apeldoorn arnhem haarlem haarlemmermeer enschede
    amersfoort zaanstad zaandam 's-hertogenbosch s-hertogenbosch den_bosch zwolle zoetermeer
    leeuwarden maastricht dordrecht ede alphen_aan_den_rijn alkmaar emmen westland delft venlo
    deventer sittard geleen helmond oss amstelveen hilversum heerlen súdwest-fryslân
    nissewaard hengelo purmerend schiedam lelystad roosendaal hoofddorp leidschendam voorburg
    vlaardingen almelo spijkenisse gouda zeist katwijk hoorn veenendaal capelle_aan_den_ijssel
    krimpen_aan_den_ijssel nieuwegein ridderkerk barendrecht doetinchem roermond weert kerkrade
    brunssum landgraaf valkenburg vaals middelburg vlissingen terneuzen zierikzee hulst
    assen hoogeveen meppel coevorden steenwijk kampen harderwijk ermelo nunspeet elburg hattem
    epe zutphen lochem winterswijk zevenaar duiven wijchen tiel culemborg wageningen barneveld
    nijkerk leusden woudenberg houten ijsselstein vianen woerden bodegraven waddinxveen
    leiderdorp oegstgeest noordwijk lisse hillegom heemstede bloemendaal zandvoort beverwijk
    heemskerk castricum heerhugowaard enkhuizen medemblik schagen den_helder texel ameland
    terschelling vlieland schiermonnikoog volendam monnickendam uithoorn aalsmeer badhoevedorp
    schiphol blaricum laren baarn soest de_bilt bilthoven maarssen breukelen rijswijk
    scheveningen wassenaar pijnacker nootdorp naaldwijk maassluis hellevoetsluis brielle
    zwijndrecht papendrecht sliedrecht gorinchem leerdam oosterhout etten-leur bergen_op_zoom
    waalwijk dongen goirle oisterwijk vught boxtel uden veghel veldhoven geldrop deurne
    valkenswaard waalre venray sneek bolsward franeker dokkum heerenveen joure drachten
    harlingen lemmer urk emmeloord dronten zeewolde delfzijl veendam stadskanaal winschoten
    hoogezand oldenzaal hardenberg haaksbergen losser rijssen raalte ommen dalfsen diemen
    weesp muiden abcoude bussum naarden huizen leiden edam ijmuiden velsen krommenie
    wormerveer kampen assen heusden drunen cuijk boxmeer gemert nuenen son_en_breugel
    zundert rucphen moerdijk halderberge steenbergen tholen goes putten buren grave beek
    bergen sluis doorn rhenen renkum oosterbeek wolvega
"""

_PLACES_BE = """
    antwerpen antwerp brussel brussels bruxelles gent ghent brugge bruges leuven mechelen
    hasselt genk oostende ostend kortrijk aalst liège liege luik charleroi namur
"""

_PLACES_WORLD = """
    london paris berlin madrid rome roma milan milano milaan munich münchen hamburg frankfurt
    köln cologne keulen düsseldorf dusseldorf stuttgart dortmund essen bremen hannover leipzig
    dresden vienna wenen wien zurich zürich geneva genève genève bern basel lyon marseille
    toulouse nice bordeaux lille nantes strasbourg barcelona valencia sevilla seville malaga
    málaga bilbao lisbon lissabon lisboa porto dublin cork edinburgh glasgow manchester
    liverpool birmingham leeds bristol sheffield newcastle cardiff belfast oxford cambridge
    reading bath brighton york copenhagen kopenhagen københavn stockholm oslo helsinki
    reykjavik warsaw warschau warszawa krakow kraków prague praag praha budapest bucharest
    boekarest sofia athens athene istanbul ankara moscow moskou kyiv kiev riga vilnius tallinn
    new_york los_angeles san_francisco san_diego chicago boston seattle miami houston dallas
    austin denver atlanta phoenix philadelphia washington detroit toronto montreal vancouver
    ottawa mexico_city são_paulo sao_paulo rio_de_janeiro buenos_aires lima bogotá bogota
    santiago tokyo tokio osaka kyoto seoul beijing peking shanghai hong_kong shenzhen taipei
    singapore singapur bangkok jakarta manila kuala_lumpur mumbai delhi new_delhi bangalore
    bengaluru chennai kolkata hyderabad karachi lahore dubai abu_dhabi doha riyadh tel_aviv
    jerusalem cairo caïro casablanca marrakech marrakesh rabat tanger tangier lagos nairobi
    johannesburg cape_town kaapstad sydney melbourne brisbane perth auckland wellington
    paramaribo willemstad oranjestad kralendijk las_vegas mobile split sale hull derby wells
"""

# Places that are also ordinary words or names: only a place after a place preposition or
# inside an address ("in Best", "near Reading", "Keizersgracht 12, Best").
AMBIGUOUS_PLACES: FrozenSet[str] = _words(
    """
    nice reading mobile best born echt made bath split sale goes putten huizen buren hoorn
    sluis grave beek bergen kampen assen leiden edam gouda doorn essen bordeaux porto cork
    oxford cambridge phoenix washington santiago sofia wellington hull derby wells lima
    perth york son_en_breugel drunen gent houten duiven weert wenen hulst austin
    """
)

PLACE_NAMES: FrozenSet[str] = frozenset(
    p.replace("_", " ")
    for p in (_words(_PLACES_NL) | _words(_PLACES_BE) | _words(_PLACES_WORLD))
) | frozenset({"best", "born", "echt", "made"})
AMBIGUOUS_PLACES = frozenset(p.replace("_", " ") for p in AMBIGUOUS_PLACES)


def _build_place_index(names: FrozenSet[str]) -> Dict[str, List[Tuple[str, ...]]]:
    """first word -> word tuples (longest first) for O(1) per-token multi-word lookups."""
    index: Dict[str, List[Tuple[str, ...]]] = {}
    for name in names:
        words = tuple(name.lstrip("'").split())
        index.setdefault(words[0], []).append(words)
    for key in index:
        index[key].sort(key=len, reverse=True)
    return index


PLACE_INDEX: Dict[str, List[Tuple[str, ...]]] = _build_place_index(PLACE_NAMES)
MAX_PLACE_WORDS = max(len(v) for vs in PLACE_INDEX.values() for v in vs)

# Prepositions that make the next capitalised word a place reference.
PLACE_PREPOSITIONS: FrozenSet[str] = _words(
    "in at to from near around outside inside te naar uit bij nabij vanuit rond via"
)

# ---------------------------------------------------------------------------------------------
# Streets. Dutch street names are one compound word ending in a suffix; English street names are
# one to three capitalised words followed by a street word.
# ---------------------------------------------------------------------------------------------
STREET_SUFFIXES_NL: Tuple[str, ...] = tuple(
    sorted(
        _words(
            """
            straat laan weg gracht kade plein singel dijk steeg hof dreef pad markt plantsoen
            wal baan park boulevard straatweg haven burgwal
            """
        ),
        key=len,
        reverse=True,
    )
)
STREET_WORDS_EN: FrozenSet[str] = frozenset(
    {
        "Street", "St", "Road", "Rd", "Avenue", "Ave", "Lane", "Ln", "Drive", "Boulevard", "Blvd",
        "Square", "Court", "Way", "Place", "Terrace", "Crescent", "Close", "Parkway", "Highway",
        "Alley", "Row", "Gardens", "Mews", "Hill", "Grove", "Walk",
    }
)

# Capitalised NL words ending in a street suffix that are ordinary nouns, not streets.
STREET_SUFFIX_STOPLIST: FrozenSet[str] = _words(
    """
    onderweg halfweg snelweg uitweg zijweg omweg arbeidsmarkt woningmarkt aandelenmarkt
    huizenmarkt geldmarkt loopbaan gerechtshof kerkhof paleis voorplein tussenpad
    """
)

# Cue words that make the following Title-Case group an organisation name ("Pay Total Security",
# "invoice from Master Audit", "leverancier Groene Energie"). The cue itself is never blinded.
ORG_CUE_PATTERN = (
    r"pay|invoice\s+(?:from|to)|vendor|supplier|client|customer|company|firm|contractor|"
    r"betaal|factuur\s+(?:van|aan)|leverancier|bedrijf|firma"
)
