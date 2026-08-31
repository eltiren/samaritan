import Foundation
import Testing
@testable import SamaritanTests

/// `sourceAppIdentifier` is `<teamID>.<bundleID>`, and the interesting cases are all about the team
/// half: it can be empty, and one app can turn up under two different values of it. That is what
/// made the Apps list show the same app twice.
@Suite("App identity")
struct AppIdentityTests {

    private let nordTeam = "W5W395V82Y.com.nordvpn.NordVPN"
    private let nordPlatform = ".com.nordvpn.NordVPN"

    // MARK: - Parsing

    @Test("A third-party identifier splits on the first dot")
    func splitsThirdParty() {
        let identity = AppIdentity(raw: nordTeam)
        #expect(identity.teamID == "W5W395V82Y")
        #expect(identity.bundleID == "com.nordvpn.NordVPN")
        #expect(identity.displayBundleID == "com.nordvpn.NordVPN")
        #expect(identity.displayTeamID == "W5W395V82Y")
    }

    /// The leading dot is the whole point: the team is empty, not missing, and splitting on the
    /// first dot has to yield the entire bundle ID rather than eating `com`.
    @Test("An empty team leaves the bundle ID intact")
    func splitsEmptyTeam() {
        let identity = AppIdentity(raw: nordPlatform)
        #expect(identity.teamID.isEmpty)
        #expect(identity.bundleID == "com.nordvpn.NordVPN")
        #expect(identity.displayTeamID == "no team")
    }

    /// Both halves matter: an empty team alone is not enough to call something Apple's.
    @Test("A platform-signed third-party flow is not an Apple system app")
    func emptyTeamIsNotAppleAlone() {
        #expect(AppIdentity(raw: nordPlatform).isAppleSystemApp == false)
        #expect(AppIdentity(raw: ".com.apple.mobilesafari").isAppleSystemApp)
    }

    // MARK: - Collisions

    /// The reported bug, in one assertion: two identifiers, one bundle ID, one row each, and the
    /// rows were indistinguishable because a row shows the bundle ID.
    @Test("One bundle ID under two teams is a collision")
    func detectsCollision() {
        let colliding = AppIdentity.collidingBundleIDs(in: [nordTeam, nordPlatform])
        #expect(colliding == ["com.nordvpn.NordVPN"])
    }

    @Test("Distinct apps do not collide")
    func distinctAppsDoNotCollide() {
        let colliding = AppIdentity.collidingBundleIDs(in: [
            nordTeam,
            "BQR82RBBHL.com.tinyspeck.chatlyio",
            ".com.apple.mobilesafari",
        ])
        #expect(colliding.isEmpty)
    }

    /// The caller concatenates the observed list and the policy-only list. A duplicate across them
    /// is the same app twice, not two apps, and labelling every such row with a team would put the
    /// noise on every row in the list.
    @Test("The same identifier repeated is not a collision")
    func repeatedIdentifierIsNotACollision() {
        #expect(AppIdentity.collidingBundleIDs(in: [nordTeam, nordTeam, nordTeam]).isEmpty)
    }

    /// An extension shares its parent's team but not its bundle ID, so it is a sibling row, not a
    /// collision — nothing about it is ambiguous on screen.
    @Test("A sibling bundle under the same team is not a collision")
    func siblingBundleIsNotACollision() {
        let colliding = AppIdentity.collidingBundleIDs(in: [
            "W5W395V82Y.com.nordvpn.NordVPN",
            "W5W395V82Y.com.nordvpn.NordVPN.widget",
        ])
        #expect(colliding.isEmpty)
    }

    @Test("Three identifiers for one bundle collide once")
    func threeWayCollision() {
        let colliding = AppIdentity.collidingBundleIDs(in: [
            nordTeam, nordPlatform, "OTHERTEAM1.com.nordvpn.NordVPN",
        ])
        #expect(colliding == ["com.nordvpn.NordVPN"])
    }

    @Test("The unattributed pseudo-identifier never collides")
    func unattributedNeverCollides() {
        let colliding = AppIdentity.collidingBundleIDs(in: [
            AppIdentity.unattributedRaw, nordTeam,
        ])
        #expect(colliding.isEmpty)
    }
}
