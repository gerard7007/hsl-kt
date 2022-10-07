import okio.ByteString.Companion.decodeBase64
import org.apache.commons.codec.digest.DigestUtils
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.*
import kotlin.math.floor
import kotlin.math.roundToInt

object HSL {
    private fun base64decode(input: String): String {
        return input.decodeBase64()!!.string(StandardCharsets.UTF_8)
    }

    fun getProof(req: String): String {
        val x = "0123456789/:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        val reqSplit = req.split(".")

        val data = JSONObject(mapOf(
            "header" to JSONObject(base64decode(reqSplit[0] + "=======")),
            "payload" to JSONObject(base64decode(reqSplit[1] + "=======")),
            "raw" to mapOf(
                "header" to reqSplit[0],
                "payload" to reqSplit[1],
                "signature" to reqSplit[2],
            )
        ))

        fun a(r: ArrayList<Int>): Boolean {
            for (t in 0 until r.size) {
                if (r[t] < x.length - 1) {
                    r[t] += 1
                    return true
                }
            }
            return false
        }

        fun z(r: ArrayList<Int>): String {
            var t = ""

            for (n in 0 until r.size) {
                t += x[r[n]]
            }

            return t
        }

        fun o(r: Int, e: String): Boolean {
            val t = DigestUtils.sha1(e)!!
            val o = ArrayList<Int>()

            for (n in 0 until 8 * t.size) {
                val j = t[floor(n / 8.0).roundToInt()].toInt() shr n % 8 and 1
                o.add(j)
            }

            val a = o.subList(0, r).toTypedArray()

            fun index2(x: Array<Int>, y: Int): Int {
                if (y in x) {
                    return x.indexOf(y)
                }
                return -1
            }

            return 0 == a[0] && index2(a, 1) >= r - 1 || -1 == index2(a, 1)
        }

        fun get(): String {
            for (e in 0 until 25) {
                val n = ArrayList<Int>()
                for (i in 0 until e) n.add(0)

                while (a(n)) {
                    val u = data.getJSONObject("payload").getString("d") + "::" + z(n)
                    if (o(data.getJSONObject("payload").getInt("s"), u)) {
                        return z(n)
                    }
                }
            }
            throw RuntimeException("Value expected")
        }

        val proof = StringJoiner(":")
            .add("1")
            .add(data.getJSONObject("payload").getInt("s").toString())
            .add(Instant.now().toString().split(".")[0]
                .replace("T", "")
                .replace("-", "")
                .replace(":", "")
            )
            .add(data.getJSONObject("payload").getString("d"))
            .add("")
            .add(get())

        return proof.toString()
    }
}

fun main() {
    val req1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmIjowLCJzIjoyLCJ0IjoidyIsImQiOiJTdGd3aU85U1dhL2NzajJQcmNuU0c1aUpyZkdoNVBNN2MyVnlxQy9JcjlHSHVuU3lOakE5bStjdk16SDdVejJnVDBzaXJhU0VyTit1RmdKUWVpNVdnc0RpVEFOL1FCWHR2V3djUG5kcGZEaTJKNkZTVjlpVWtnamRoa2oyQ0RPUGdZQXpuYlFFSzJaOEh6dXpYdUMydlpJenRVNEEyQnJqVHY2K3VBclZCWUcwNmFyZEJCR1dsWmt5Y3c9PVgwRkkrRllNN2VPME5UQ2QiLCJsIjoiaHR0cHM6Ly9uZXdhc3NldHMuaGNhcHRjaGEuY29tL2MvOWZiMDczNTYiLCJlIjoxNjY1MTE2MzY2LCJuIjoiaHN3IiwiYyI6MTAwMH0.0-ING_4K8KJo-bN6ci8laVjYKgdtrANUqQwoFXYRg64"
    val req2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmIjowLCJzIjoyLCJ0IjoidyIsImQiOiJSUW9IaXhXeE9Da3YzY0NKajNxMVluTFp5Y0c2ZVdQaC9QQlNBVWw1NzJVTnREUTd4WVV4V1FEK2k5Wk41R1Q1VTdJb1RaSHFKWHRXUVZlNlpiS1hpNkJKd0hXdHpUbFhZTGlqY1VuNUhWalhYamxQZk5sb3pkY2R5WEVzT0JTZEI1QWU1MzdHS2hZTVliVUJJeFExZkE5UzBrVUR6MUladlRidXNDMXRQeGhrdjdvNE92dnpMdmZwSUE9PXlIcVk1MmdLMFIrbmsxeXIiLCJsIjoiaHR0cHM6Ly9uZXdhc3NldHMuaGNhcHRjaGEuY29tL2MvOWZiMDczNTYiLCJlIjoxNjY1MTY5NDEzLCJuIjoiaHN3IiwiYyI6MTAwMH0.CIKdd782JPqsHNthy7HzBvRfvgWDU61enVTjHDhJTZw"

    println(HSL.getProof(req1))
}
